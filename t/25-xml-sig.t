use strict;
use warnings;
use Test::Lib;
use Test::Net::SAML2;
use URI;

use Net::SAML2::XML::Sig;
use URN::OASIS::SAML2 qw(:urn);
my $urn = URN_ASSERTION;


my $sig = Net::SAML2::XML::Sig->new({ key => 't/sign-nopw-cert.pem' });
my $xml = q{
<foo ID="abc">
    <bar>123</bar>
</foo>
};

my $s = $sig->sign($xml);

my $first_line = (split /\n/, $s)[0];
my $xml_decl   = '<?xml version="1.0"?>';
is($first_line, $xml_decl, "Got the $xml_decl");

my $xp = get_xpath(
    $s,
    ds   => URN_SIGNATURE,
    xenc => URN_ENCRYPTION,
);

my $root     = $xp->getContextNode->documentElement;
my @children = $root->nonBlankChildNodes;
is(@children, 2, "We have two children");
cmp_deeply(
    [map { $_->localname } @children],
    [qw(bar Signature)],
    "... with the correct local names"
);

{
    my $sig = Net::SAML2::XML::Sig->new(
        { key => 't/sign-nopw-cert.pem', no_xml_declaration => 1 });
    my $xml = q{
<foo ID="abc">
<bar>123</bar>
</foo>
};

    my $s = $sig->sign($xml);

    my $first_line = (split /\n/, $s)[0];
    my $xml_decl   = '<?xml version="1.0"?>';
    isnt($first_line, $xml_decl, "Got the $xml_decl");
}

{
    my $sig = Net::SAML2::XML::Sig->new({ key => 't/sign-nopw-cert.pem' });

    my $urn = URN_ASSERTION,
    my $xml = qq{
<saml:Xml xmlns:saml="$urn">
<saml:Issuer>FooBar</saml:Issuer>
<saml:Foo ID="bar">
<saml:bar>foo</saml:bar>
</saml:Foo>
</saml:Xml>
};
    my $s = $sig->sign($xml);
my $xp = get_xpath(
    $s,
    ds   => URN_SIGNATURE,
    xenc => URN_ENCRYPTION,
    saml => $urn,
);

my $root     = $xp->getContextNode->documentElement;
is($root->localname, 'Xml', 'Root of the XML is correct');
my @children = $root->nonBlankChildNodes;
is(@children, 3, "We have two children");
cmp_deeply(
    [map { $_->localname } @children],
    [qw(Issuer Signature Foo)],
    "... with the correct local names"
);

}


done_testing;
