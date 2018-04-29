use strict;
use warnings;
package Net::SAML2::Util;
# VERSION

use Exporter qw(import);

use Carp qw(croak);
use Crypt::OpenSSL::Random qw(random_pseudo_bytes);
use XML::LibXML::XPathContext;
use XML::LibXML;

# ABSTRACT: Utility functions for Net:SAML2


our @EXPORT = qw();
our @EXPORT_OK = qw(
    generate_id
    get_xpath
    get_soap_body
);

our %EXPORT_TAGS = (
    all => [@EXPORT, @EXPORT_OK],
);

sub generate_id {
    my $bytes = shift || 16;
    return 'NETSAML2_' . unpack 'H*', random_pseudo_bytes($bytes);
}

sub get_xpath {
    my ($xml, %ns) = @_;

    my $xp = XML::LibXML::XPathContext->new(
        XML::LibXML->load_xml(string => $xml)
    );

    $xp->registerNs($_, $ns{$_}) foreach keys %ns;

    return $xp;
}

sub get_soap_body {
    my $xml = shift;

    my $xp = get_xpath(
        $xml,
        'soap-env' => 'http://schemas.xmlsoap.org/soap/envelope/',
        @_,
    );

    my @nodes = $xp->findnodes('/soap-env:Envelope/soap-env:Body/*[1]');
    if (@nodes) {
        return $nodes[0]->toString;
    }

    croak "Unable to extract SOAP body from xml: $xml" unless(@nodes);
}

1;

__END__

=head1 DESCRIPTION

=head1 SYNOPSIS

    use Net::SAML2::Util qw(generate_id);

=head1 METHODS

=head2 sub generate_id($bytes)

Generate a NETSAML2 Request ID. Defaults to a 16 byte random

=head2 get_xpath($xml, namespace => 'https://example.com/ns')

Return a L<XML::LibXML::XPathContext> object.

=head2 get_soap_body($xml);

Get the SOAP body as a string literal.

