use strict;
use warnings;
package Net::SAML2::Binding::SOAP;

use Carp;
use HTTP::Request::Common;
use LWP::UserAgent;

use HTTP::Request::Common;
use LWP::UserAgent;
use Moose;
use MooseX::Types::URI qw/ Uri /;
use Net::SAML2::Util qw(:all);
use Net::SAML2::XML::Sig;
use Net::SAML2::XML::Util qw/ no_comments /;
use XML::LibXML;

# ABSTRACT: Net::SAML2::Binding::Artifact - SOAP binding for SAML

=head1 NAME

Net::SAML2::Binding::Artifact - SOAP binding for SAML2

=head1 SYNOPSIS

  my $soap = Net::SAML2::Binding::SOAP->new(
    url => $idp_url,
    key => $key,
    cert => $cert,
    idp_cert => $idp_cert,
  );

  my $response = $soap->request($req);

=head1 METHODS

=cut

=head2 new( ... )

Constructor. Returns an instance of the SOAP binding configured for
the given IdP service url.

Arguments:

=over

=item B<ua>

(optional) a LWP::UserAgent-compatible UA

=item B<url>

the service URL

=item B<key>

the key to sign with

=item B<cert>

the corresponding certificate

=item B<idp_cert>

the idp's signing certificate

=item B<cacert>

the CA for the SAML CoT

=back

=cut

has 'ua' => (
    isa      => 'Object',
    is       => 'ro',
    required => 1,
    default  => sub { LWP::UserAgent->new }
);

has 'url'      => (isa => Uri, is => 'ro', required => 1, coerce => 1);
has 'key'      => (isa => 'Str', is => 'ro', required => 1);
has 'cert'     => (isa => 'Str', is => 'ro', required => 1);
has 'idp_cert' => (isa => 'Str', is => 'ro', required => 1);
has 'cacert'   => (isa => 'Str', is => 'ro', required => 1);

=head2 request( $message )

Submit the message to the IdP's service.

Returns the Response, or dies if there was an error.

=cut

sub request {
    my ($self, $message) = @_;
    my $request = $self->create_soap_envelope($message);

    my $soap_action = 'http://www.oasis-open.org/committees/security';

    my $req = POST $self->url;
    $req->header('SOAPAction' => $soap_action);
    $req->header('Content-Type' => 'text/xml');
    $req->header('Content-Length' => length $request);
    $req->content($request);

    my $res = $self->assert_request($req);

    return $self->handle_response($res);
}

sub assert_request {
    my ($self, $request) = @_;

    my $res =$self->ua->request($request);
    return $res->decoded_content if $res->is_success;
    die "Request returned an invalid response: " . $res->as_string;
}

=head2 handle_response( $response )

Handle a response from a remote system on the SOAP binding.

Accepts a string containing the complete SOAP response.

=cut

sub handle_response {
    my ($self, $response) = @_;

    my $xml = get_soap_body($response);
    my $cert = $self->verify_saml($xml);
    my $subject = sprintf("%s (verified)", $cert->subject);

    return ($subject, $xml);
}

sub verify_saml {
    my ($self, $xml) = @_;

    my $sig = Net::SAML2::XML::Sig->new(
        {
            cert_text          => $self->idp_cert,
            exclusive          => 1,
            no_xml_declaration => 1,
            x509               => 1,
        }
    );
    # TODO: Does this still exist?
    $sig->assert($xml);

    # verify the signing certificate
    my $cert = $sig->signer_cert;
    my $ca = Crypt::OpenSSL::VerifyX509->new($self->cacert,
        { strict_certs => 0 });

    if (!$ca->verify($cert)) {
        croak "Bad signer certificate for" . $cert->subject;
    }
    return $cert;
}

=head2 handle_request( $request )

Handle a request from a remote system on the SOAP binding.

Accepts a string containing the complete SOAP request.

=cut

sub handle_request {
    my ($self, $request) = @_;

    my $dom = no_comments($request);
     my $saml = get_soap_body($request);

    # TODO: check if this still works
    # my $cert = $self->verify_saml($saml);
    # my $subject = $cert->subject;
    # return ($subject, $saml);
    if (defined $saml) {
        my $x = Net::SAML2::XML::Sig->new({ x509 => 1, cert_text => $self->idp_cert, exclusive => 1, });
        my $ret = $x->verify($saml);
        die "bad signature" unless $ret;

        my $cert = $x->signer_cert;
        my $ca = Crypt::OpenSSL::Verify->new($self->cacert, { strict_certs => 0, });
        $ret = $ca->verify($cert);
        die "bad certificate in request: ".$cert->subject unless $ret;

        my $subject = $cert->subject;
        return ($subject, $saml);
    }

    return;
}

=head2 create_soap_envelope( $message )

Signs and SOAP-wraps the given message.

=cut

sub create_soap_envelope {
    my ($self, $message) = @_;

    # sign the message
    my $sig = Net::SAML2::XML::Sig->new({
        x509 => 1,
        key  => $self->key,
        cert => $self->cert,
        exclusive => 1,
        no_xml_declaration => 1,
    });
    my $signed_message = $sig->sign($message);

    # OpenSSO ArtifactResolve hack
    #
    # OpenSSO's ArtifactResolve parser is completely hateful. It demands that
    # the order of child elements in an ArtifactResolve message be:
    #
    # 1: saml:Issuer
    # 2: dsig:Signature
    # 3: samlp:Artifact
    #
    # Really.
    #
    if ($signed_message =~ /ArtifactResolve/) {
        $signed_message =~ s!(<dsig:Signature.*?</dsig:Signature>)!!s;
        my $signature = $1;
        $signed_message =~ s/(<\/saml:Issuer>)/$1$signature/;
    }

    # test verify
    my $ret = $sig->verify($signed_message);
    die "failed to sign" unless $ret;

    my $soap = <<"SOAP";
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
<SOAP-ENV:Body>
$signed_message
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>
SOAP
    return $soap;
}

__PACKAGE__->meta->make_immutable;

