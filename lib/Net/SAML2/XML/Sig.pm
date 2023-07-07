package Net::SAML2::XML::Sig;
use strict;
use warnings;

#VERSION

# ABSTRACT: Net::SAML2 subclass of XML::Sig

use parent qw(XML::Sig);

use XML::LibXML;
use XML::LibXML::XPathContext;
use URN::OASIS::SAML2 qw(:urn);

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
    # The real fix here is to fix XML::Sig to accept a XPATH to
    # place the signature in the correct location.  Or use XML::LibXML
    # here to do so
    #
    # The protocol schema defines a sequence which requires the order
    # of the child elements in a Protocol based message:
    #
    # The dsig:Signature (should it exist) MUST follow the saml:Issuer
    #
    # 1: saml:Issuer
    # 2: dsig:Signature
    #
    # Seems like an oversight in the SAML schema specifiation but...
    #
    my $dom = XML::LibXML->load_xml(string => $xml);
    my $xp  = XML::LibXML::XPathContext->new($dom);
    $xp->registerNs('saml', URN_ASSERTION);
    $xp->registerNs('samlp', URN_PROTOCOL);
    $xp->registerNs('ds', URN_SIGNATURE);

    my $issuer = $xp->findnodes('//saml:Issuer');
    return $xml unless $issuer->size;
    $issuer = $issuer->get_node(1);

    my $sig = $xp->findnodes('//ds:Signature');
    return $xml unless $sig->size == 1;

    $sig = $sig->get_node(1);
    $sig->unbindNode;
    my $parent = $issuer->parentNode;
    $parent->insertAfter($sig, $issuer);

    local $XML::LibXML::skipXMLDeclaration = $self->{no_xml_declaration};
    return $xp->getContextNode->toString;
}



1;
