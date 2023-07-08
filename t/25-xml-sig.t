use strict;
use warnings;
use Test::Lib;
use Test::Net::SAML2;
use URI;

use Net::SAML2::XML::Sig;
use URN::OASIS::SAML2 qw(:urn);
use MIME::Base64 qw/decode_base64/;

my $urn = URN_ASSERTION;
#$Net::SAML2::XML::Sig::DEBUG = 1;
#$XML::Sig::DEBUG = 1;

my $sig = Net::SAML2::XML::Sig->new({ key => 't/sign-nopw-cert.pem' });
my $xml = q{
<foo ID="12345">
    <bar>123</bar>
</foo>
};

diag $XML::Sig::VERSION;

my $s  = $sig->sign($xml);

test_signature_ok($s, 'foo', qw(bar Signature));
my $first_line = (split /\n/, $s)[0];
my $xml_decl   = '<?xml version="1.0"?>';
is($first_line, $xml_decl, "Got the $xml_decl");

sub test_signature_ok {
    my $xml = shift;
    my $local_name = shift;
    my @expect = @_;

    my $xp = get_xpath(
        $xml,
        ds   => URN_SIGNATURE,
        xenc => URN_ENCRYPTION,
        saml => $urn,
    );

    my $root = $xp->getContextNode->documentElement;
    is($root->localname, $local_name, 'Root of the XML is correct: $localname');
    my @children = $root->nonBlankChildNodes;

    my $ok = cmp_deeply(
        [map { $_->localname } @children],
        \@expect,
        "... with the correct local names"
    );

    return $ok if $ok;

    diag explain [map { $_->localname } @children];
    diag explain \@expect;
    diag $root;
}

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
    isnt($first_line, $xml_decl, "Did not get the $xml_decl");
}

{
    my $sig = Net::SAML2::XML::Sig->new({ key => 't/sign-nopw-cert.pem' });

    my $urn = URN_ASSERTION;
my $xml = qq{
<saml:Xml xmlns:saml="$urn" ID="bar">
<saml:Issuer>FooBar</saml:Issuer>
<saml:Foo ID="foo">
<saml:bar>foo</saml:bar>
</saml:Foo>
</saml:Xml>
};

    test_signature_ok($xml, 'Xml', qw(Issuer Foo));
}


{
    my $sig = Net::SAML2::XML::Sig->new({ key => 't/sign-nopw-cert.pem' });
    open my $fh, '<', 't/data/signed-signature-unordered.xml';
    my $xml;
    { 
        local $/ = undef;
        $xml = <$fh>;
        close($fh);
    }


    my $post = $sig->sign($xml);
    test_signature_ok($xml, 'Response', qw(Issuer Status Assertion));
    diag $post;

    my $verifyXML = Net::SAML2::XML::Sig->new(
        {
            key       => 't/sign-nopw-cert.pem',
            x509      => 1,
            exclusive => 1
        }
    );

    ok($verifyXML->verify($post),
        "We verified the XML as Net::SAML2::Role::VerifyXML::verify_xml");

}


done_testing;
