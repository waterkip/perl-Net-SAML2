package Net::SAML2::XML::Sig;
use strict;
use warnings;

#VERSION

# ABSTRACT: Net::SAML2 subclass of XML::Sig

use parent qw(XML::Sig);

use XML::LibXML;
use XML::LibXML::XPathContext;
use URN::OASIS::SAML2 qw(:urn);
use List::Util qw(uniq);

my $DEBUG = 0;

sub sign {
    my $self = shift;

    my $xml = $self->SUPER::sign(@_);
    return $self->_fix_signature_location($xml);
}

sub _fix_signature_location {
    my $self = shift;
    my $xml = shift;

    # saml-schema-protocol-2.0.xsd Schema hack
    #
    # The protocol schema defines a sequence which requires the order
    # of the child elements in a Protocol based message:
    #
    # The dsig:Signature (should it exist) MUST follow the saml:Issuer
    #
    # 1: saml:Issuer
    # 2: dsig:Signature
    #
    my $dom = XML::LibXML->load_xml(string => $xml);
    my $xp  = XML::LibXML::XPathContext->new($dom);
    $xp->registerNs('saml', URN_ASSERTION);
    $xp->registerNs('samlp', URN_PROTOCOL);
    $xp->registerNs('ds', URN_SIGNATURE);

    _remove_data_from_xml($xml, 'pre-fix.xml') if $DEBUG;

    my $issuers = $xp->findnodes('//saml:Issuer');
    return $xml unless $issuers->size;

    $issuers->foreach(
        sub {
            my $issuer = $_;
            my $parent = $issuer->parentNode;
            my $ids = $xp->findnodes('//@ID', $issuer);
            my @ids = uniq $ids->map(sub { $_->getValue });

            my $sig = $xp->findnodes('//ds:Signature//@URI');
            $sig->foreach(
                sub {
                    my $node = $_->parentNode->parentNode->parentNode;
                    $node->unbindNode;
                    $parent->insertAfter($node, $issuer);
                }
            );
        }
    );

    local $XML::LibXML::skipXMLDeclaration = $self->{no_xml_declaration};
    $xml = $xp->getContextNode->toString;

    _remove_data_from_xml($xml, 'post-fix.xml') if $DEBUG;

    return $xml;
}

sub _remove_data_from_xml {
    my $xml = shift;
    my $filename = shift;
    return unless $DEBUG;

    my $dom = XML::LibXML->load_xml(string => $xml);
    my $xp  = XML::LibXML::XPathContext->new($dom);
    $xp->registerNs('saml', URN_ASSERTION);
    $xp->registerNs('samlp', URN_PROTOCOL);
    $xp->registerNs('ds', URN_SIGNATURE);

    $xp->findnodes('//dsig:SignatureValue')->foreach(
        sub {
            $_->removeChildNodes;
            $_->appendText('Signature value removed');
        }
    );

    $xp->findnodes('//dsig:X509Certificate')->foreach(
        sub {
            $_->removeChildNodes;
            $_->appendText('X509Certificate value removed');
        }
    );

    $xml = $xp->getContextNode->toString;
    open my $fh, '>', $filename;
    print $fh $xml;
    close($fh);
}

1;
