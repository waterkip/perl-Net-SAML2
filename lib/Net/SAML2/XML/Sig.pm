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

    _remove_data_from_xml($xml, 'pre-fix.xml');

    return $xml unless $xp->exists('//saml:Issuer');

    my $ids = $xp->findnodes('//@ID');
    $ids->foreach(
        sub {
            my $parent = $_->parentNode;
            my $issuers = $xp->findnodes('./saml:Issuer', $parent);
            return unless $issuers->size;
            my $issuer = $issuers->get_node(1);
            my $ip = $issuer->parentNode;
            my $sig = $xp->findnodes(sprintf('//ds:Signature/ds:SignedInfo/ds:Reference[@URI="#%s"]/..', $_->getValue));
            $sig->foreach(
                sub {
                    my $node = $_->parentNode;
                    $node->unbindNode;
                    $ip->insertAfter($node, $issuer);
                }
            );
        }
    );


    local $XML::LibXML::skipXMLDeclaration = $self->{no_xml_declaration};
    $xml = $xp->getContextNode->toString;

    _remove_data_from_xml($xml, 'post-fix.xml');

    return $xml;
}

sub _remove_data_from_xml {
    my $xml = shift;
    my $filename = shift;

    my $dom = XML::LibXML->load_xml(string => $xml);
    my $xp  = XML::LibXML::XPathContext->new($dom);
    $xp->registerNs('saml', URN_ASSERTION);
    $xp->registerNs('samlp', URN_PROTOCOL);
    $xp->registerNs('ds', URN_SIGNATURE);

    $xp->findnodes('//ds:SignatureValue')->foreach(
        sub {
            $_->removeChildNodes;
            $_->appendText('Signature value removed');
        }
    ) if $DEBUG;

    $xp->findnodes('//ds:X509Certificate')->foreach(
        sub {
            $_->removeChildNodes;
            $_->appendText('X509Certificate value removed');
        }
    ) if $DEBUG;

    $xml = $xp->getContextNode->toString;
    open my $fh, '>', $filename;
    print $fh $xml;
    close($fh);
}

1;
