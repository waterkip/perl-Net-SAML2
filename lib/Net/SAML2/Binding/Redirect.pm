use strict;
use warnings;
package Net::SAML2::Binding::Redirect;
# VERSION

use Moose;
use MooseX::Types::URI qw/ Uri /;
use Net::SAML2::Types qw(signingAlgorithm SAMLRequestType);
use Carp qw(croak);

# ABSTRACT: Net::SAML2::Binding::Redirect - HTTP Redirect binding for SAML

=head1 NAME

Net::SAML2::Binding::Redirect

=head1 SYNOPSIS

  my $redirect = Net::SAML2::Binding::Redirect->new(
    key     => '/path/to/SPsign-nopw-key.pem',		# Service Provider (SP) private key
    url     => $sso_url,							# Service Provider Single Sign Out URL
    param   => 'SAMLRequest' OR 'SAMLResponse',		# Type of request
    cert    => $idp->cert('signing')				# Identity Provider (IdP) certificate
    sig_hash => 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'  # Signature to sign request
  );

  my $url = $redirect->sign($authnreq);

  my $ret = $redirect->verify($url);

=head1 METHODS

=cut

use MIME::Base64 qw/ encode_base64 decode_base64 /;
use IO::Compress::RawDeflate qw/ rawdeflate /;
use IO::Uncompress::RawInflate qw/ rawinflate /;
use URI;
use URI::QueryParam;
use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::X509;
use File::Slurper qw/ read_text /;
use URI::Encode qw/uri_decode/;

=head2 new( ... )

Constructor. Creates an instance of the Redirect binding.

Arguments:

=over

=item B<key>

The SP's (Service Provider) also known as your application's signing key
that your application uses to sign the AuthnRequest.  Some IdPs may not
verify the signature.

=item B<cert>

IdP's (Identity Provider's) certificate that is used to verify a signed
Redirect from the IdP.  It is used to verify the signature of the Redirect
response.

=item B<url>

IdP's SSO (Single Sign Out) service url for the Redirect binding

=item B<param>

query param name to use (SAMLRequest, SAMLResponse)
Defaults to C<SAMLRequest>.

=item B<sig_hash>

RSA hash to use to sign request

Supported:

sha1, sha224, sha256, sha384, sha512

Defaults to C<sha1>.

=item B<sls_force_lcase_url_encoding>

Specifies that the IdP requires the encoding of a URL to be in lowercase.
Necessary for a HTTP-Redirect of a LogoutResponse from Azure in particular.
True (1) or False (0). Some web frameworks and underlying http requests assume
that the encoding should be in the standard uppercase (%2F not %2f)

=item B<sls_double_encoded_response>

Specifies that the IdP response sent to the HTTP-Redirect is double encoded.
The double encoding requires it to be decoded prior to processing.

=back

=cut

has 'cert' => (isa => 'ArrayRef', is => 'ro', required => 0, predicate => 'has_cert');
has 'url'  => (isa => Uri, is => 'ro', required => 0, coerce => 1, predicate => 'has_url');
has 'key'  => (isa => 'Str', is => 'ro', required => 0, predicate => 'has_key');

has 'param' => (
    isa      => SAMLRequestType,
    is       => 'ro',
    required => 0,
    default  => 'SAMLRequest'
);

has 'sig_hash' => (
    isa      => signingAlgorithm,
    is       => 'ro',
    required => 0,
    default  => 'sha1'
);

has 'sls_force_lcase_url_encoding' => (
    isa      => 'Bool',
    is       => 'ro',
    required => 0,
    default  => 0
);

has 'sls_double_encoded_response' => (
    isa      => 'Bool',
    is       => 'ro',
    required => 0,
    default  => 0
);

=for Pod::Coverage BUILD

=cut

sub BUILD {
    my $self = shift;

    if ($self->param eq 'SAMLRequest') {
        croak("Need to have an URL specified") unless $self->has_url;
        croak("Need to have a key specified") unless $self->has_key;
    }
    if ($self->param eq 'SAMLResponse') {
        croak("Need to have a cert specified") unless $self->has_cert;
    }
    # other params don't need to have these per-se
}

# BUILDARGS

# Earlier versions expected the cert to be a string.  However, metadata
# can include multiple signing certificates so the $idp->cert is now
# expected to be an arrayref to the certificates.  To avoid breaking existing
# applications this changes the the cert to an arrayref if it is not
# already an array ref.

around BUILDARGS => sub {
    my $orig = shift;
    my $self = shift;

    my %params = @_;
    if ($params{cert} && ref($params{cert}) ne 'ARRAY') {
            $params{cert} = [$params{cert}];
    }

    return $self->$orig(%params);
};

=head2 sign( $request, $relaystate )

Signs the given request, and returns the URL to which the user's
browser should be redirected.

Accepts an optional RelayState parameter, a string which will be
returned to the requestor when the user returns from the
authentication process with the IdP.

=cut

sub sign {
    my ($self, $request, $relaystate) = @_;

    my $input = "$request";
    my $output = '';

    rawdeflate \$input => \$output;
    my $req = encode_base64($output, '');

    my $u = URI->new($self->url);
    $u->query_param($self->param, $req);
    $u->query_param('RelayState', $relaystate) if defined $relaystate;

    my $key_string = read_text($self->key);
    my $rsa_priv = Crypt::OpenSSL::RSA->new_private_key($key_string);

    my $method = "use_" . $self->sig_hash . "_hash";
    $rsa_priv->$method;

    $u->query_param('SigAlg',
        $self->sig_hash eq 'sha1'
        ? 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
        : 'http://www.w3.org/2001/04/xmldsig-more#rsa-' . $self->sig_hash);

    my $to_sign = $u->query;
    my $sig = encode_base64($rsa_priv->sign($to_sign), '');
    $u->query_param('Signature', $sig);

    return $u->as_string;
}

=head2 verify( $url )

Decode a Redirect binding URL.

Verifies the signature on the response.

=cut

sub verify {
    my ($self, $url) = @_;
    my $u = URI->new($url);

    # verify the response
    my $sigalg = $u->query_param('SigAlg');

    my $signed;
    my $saml_request;
    my $sig = $u->query_param_delete('Signature');

    # During the verify the only query parameters that should be in the query are
    # 'SAMLRequest', 'RelayState', 'Sig', 'SigAlg' the other parameter values are
    # deleted from the URI query that was created from the URL that was passed
    # to the verify function
    my @signed_params = ('SAMLRequest', 'SAMLResponse', 'RelayState', 'Sig', 'SigAlg');

    for my $key ($u->query_param) {
        if (grep /$key/, @signed_params ) {
            next;
        }
        $u->query_param_delete($key);
    }

    # Some IdPs (PingIdentity) seem to double encode the LogoutResponse URL
    if ($self->sls_double_encoded_response) {
        #if ($sigalg =~ m/%/) {
        $signed = uri_decode($u->query);
        $sig = uri_decode($sig);
        $sigalg = uri_decode($sigalg);
        $saml_request = uri_decode($u->query_param($self->param));
    } else {
        $signed = $u->query;
        $saml_request = $u->query_param($self->param);
    }

    # What can we say about this one Microsoft Azure uses lower case in the
    # URL encoding %2f not %2F.  As it is signed as %2f the resulting signed
    # needs to change it to lowercase if the application layer reencoded the URL.
    if ($self->sls_force_lcase_url_encoding) {
        # TODO: This is a hack.
        $signed =~ s/(%..)/lc($1)/ge;
    }

    $sig = decode_base64($sig);

    foreach my $crt (@{ $self->cert }) {
        for my $use (keys %{$crt}) {
            my $cert = Crypt::OpenSSL::X509->new_from_string($crt->{$use});
            my $rsa_pub = Crypt::OpenSSL::RSA->new_public_key($cert->pubkey);

            if ($sigalg eq 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256') {
                $rsa_pub->use_sha256_hash;
            } elsif ($sigalg eq 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha224') {
                $rsa_pub->use_sha224_hash;
            } elsif ($sigalg eq 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384') {
                $rsa_pub->use_sha384_hash;
            } elsif ($sigalg eq 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512') {
                $rsa_pub->use_sha512_hash;
            } elsif ($sigalg eq 'http://www.w3.org/2000/09/xmldsig#rsa-sha1') {
                $rsa_pub->use_sha1_hash;
            } else {
                die "Unsupported Signature Algorithim: $sigalg";
            }
            die "bad sig" unless $rsa_pub->verify($signed, $sig);
        }
    }
    # unpack the SAML request
    my $deflated = decode_base64($saml_request);
    my $request = '';
    rawinflate \$deflated => \$request;

    # unpack the relaystate
    my $relaystate = $u->query_param('RelayState');

    return ($request, $relaystate);
}

__PACKAGE__->meta->make_immutable;
