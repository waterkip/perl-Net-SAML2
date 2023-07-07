use strict;
use warnings;
package Net::SAML2::Binding::POST;
# VERSION

use Moose;
use Carp qw(croak);

# ABSTRACT: HTTP POST binding for SAML

=head1 NAME

Net::SAML2::Binding::POST - HTTP POST binding for SAML2

=head1 SYNOPSIS

  my $post = Net::SAML2::Binding::POST->new(
    cacert => '/path/to/ca-cert.pem'
  );
  my $ret = $post->handle_response(
    $saml_response
  );

=head1 METHODS

=cut

use Net::SAML2::XML::Sig;
use MIME::Base64 qw/ decode_base64 /;
use Crypt::OpenSSL::Verify;
use MIME::Base64;
use URI::Escape;

with 'Net::SAML2::Role::VerifyXML';

=head2 new( )

Constructor. Returns an instance of the POST binding.

Arguments:

=over

=item B<cacert>

path to the CA certificate for verification

=back

=cut

has 'cert_text' => (isa => 'Str', is => 'ro');
has 'cacert' => (isa => 'Maybe[Str]', is => 'ro');

has 'cert' => (isa => 'Str', is => 'ro', required => 0, predicate => 'has_cert');
has 'key'  => (isa => 'Str', is => 'ro', required => 0, predicate => 'has_key');

=head2 handle_response( $response )

Decodes and verifies the response provided, which should be the raw
Base64-encoded response, from the SAMLResponse CGI parameter.

=cut

sub handle_response {
    my ($self, $response) = @_;

    # unpack and check the signature
    my $xml = decode_base64($response);

    $self->verify_xml(
        $xml,
        no_xml_declaration => 1,
        $self->cert_text ? (
            cert_text => $self->cert_text
        ) : (),
        $self->cacert ? (
            cacert => $self->cacert
        ) : (),

    );
    return $xml;
}

=head2 sign_xml( $request )

Sign and encode the SAMLRequest.

=cut

sub sign_xml {
    my ($self, $request) = @_;

    croak("Need to have a cert specified") unless $self->has_cert;
    croak("Need to have a key specified") unless $self->has_key;

    my $signer = Net::SAML2::XML::Sig->new({
                        key => $self->key,
                        cert => $self->cert,
                        no_xml_declaration => 1,
                    }
                );

    return encode_base64($signer->sign($request) . "\n");

}
__PACKAGE__->meta->make_immutable;
