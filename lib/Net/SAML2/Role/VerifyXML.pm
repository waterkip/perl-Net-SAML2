package Net::SAML2::Role::VerifyXML;
use Moose::Role;
# VERSION

use Net::SAML2::XML::Sig;
use Crypt::OpenSSL::Verify;
use Crypt::OpenSSL::X509;
use Carp qw(croak);
use List::Util qw(none);

# ABSTRACT: A role to verify the SAML response XML

=head1 DESCRIPTION

=head1 SYNOPSIS

    use Net::SAML2::Some::Module;

    use Moose;
    with 'Net::SAML2::Role::VerifyXML';

    sub do_something_with_xml {
        my $self = shift;
        my $xml  = shift;

        $self->verify_xml($xml,
            # Most of these options are passed to Net::SAML2::XML::Sig, except for the
            # cacert
            # Most options are optional
            cacert    => $self->cacert,
            cert_text => $self->cert,
            no_xml_declaration => 1,
        );
    }

=cut


=head1 METHODS

=head2 verify_xml($xml, %args)

    $self->verify_xml($xml,
        # Most of these options are passed to Net::SAML2::XML::Sig, except for the
        # cacert
        # Most options are optional
        cert_text => $self->cert,
        no_xml_declaration => 1,

        # Used for a trust model, if lacking, everything is trusted
        cacert  => $self->cacert,
        # or check specific certificates based on subject/issuer or issuer hash
        anchors => {
            # one of the following is allowed
            subject     => ["subject a",     "subject b"],
            issuer      => ["Issuer A",      "Issuer B"],
            issuer_hash => ["Issuer A hash", "Issuer B hash"],
        },
    );

=cut

sub verify_xml {
    my $self = shift;
    my $xml  = shift;
    my %args = @_;

    my $cacert   = delete $args{cacert};
    my $anchors  = delete $args{anchors};

    my $x = Net::SAML2::XML::Sig->new({
        x509      => 1,
        exclusive => 1,
        %args,
    });

    croak("XML signature check failed") unless $x->verify($xml);

    if (!$anchors && !$cacert) {
        return 1;
    }

    my $cert = $x->signer_cert
        or die "Certificate not provided in SAML Response, cannot validate\n";

    if ($cacert) {
        my $ca = Crypt::OpenSSL::Verify->new($cacert, { strict_certs => 0 });
        eval { $ca->verify($cert) };
        if ($@) {
            croak("Could not verify CA certificate: $@");
        }
    }

    return 1 if !$anchors;

    if (ref $anchors ne 'HASH') {
        croak("Unable to verify anchor trust");
    }

    my ($key) = keys %$anchors;
    if (none { $key eq $_ } qw(subject issuer issuer_hash)) {
        croak("Unable to verify anchor trust, requires subject, issuer or issuer_hash");
    }

    my $got = $cert->$key;
    my $want = $anchors->{$key};
    if (!ref $want) {
        $want = [ $want ];
    }

    if (none { $_ eq $got } @$want) {
        croak("Could not verify trust anchors of certificate!");
    }
    return 1;

}


1;

__END__

