package Net::SAML2::Object::Response;
use Moose;


use overload '""' => 'to_string';

# ABSTRACT: A response object

use MooseX::Types::DateTime qw/ DateTime /;
use MooseX::Types::Common::String qw/ NonEmptySimpleStr /;
use DateTime;
use DateTime::HiRes;
use DateTime::Format::XSD;
use Net::SAML2::XML::Util qw/ no_comments /;
use Net::SAML2::XML::Sig;
use XML::Enc;
use XML::LibXML::XPathContext;
use List::Util qw(first);
use URN::OASIS::SAML2 qw(STATUS_SUCCESS URN_ASSERTION URN_PROTOCOL);
use Carp qw(croak);

with 'Net::SAML2::Role::ProtocolMessage';

# ABSTRACT: SAML2 response object

has _dom => (
    is       => 'ro',
    isa      => 'XML::LibXML::Node',
    init_arg => 'dom',
    required => 1,
);

has status => (
    is       => 'ro',
    isa      => 'Str',
    required => 1,
);

has sub_status => (
    is        => 'ro',
    isa       => 'Str',
    required  => 0,
    predicate => 'has_sub_status',
);

has assertions => (
    is       => 'ro',
    isa      => 'XML::LibXML::NodeList',
    required => 0,
    predicate => 'has_assertions',
);

sub new_from_xml {
    my $self = shift;
    my %args = @_;

    my $xml = no_comments($args{xml});

    my $xpath = XML::LibXML::XPathContext->new($xml);
    $xpath->registerNs('saml',  URN_ASSERTION);
    $xpath->registerNs('samlp', URN_PROTOCOL);

    my $response = $xpath->findnodes('/samlp:Response|/samlp:ArtifactResponse');
    croak("Unable to parse response") unless $response->size;
    $response = $response->get_node(1);

    my $code_path = 'samlp:Status/samlp:StatusCode';
    if ($response->nodePath eq '/samlp:ArtifactResponse') {
      $code_path = "samlp:Response/$code_path";
    }

    my $status = $xpath->findnodes($code_path, $response);
    croak("Unable to parse status from response") unless $status->size;

    my $status_node = $status->get_node(1);
    $status = $status_node->getAttribute('Value');

    my $substatus = $xpath->findvalue('samlp:StatusCode/@Value', $status_node);

    my $nodes = $xpath->findnodes('//saml:EncryptedAssertion|//saml:Assertion', $response);

    return $self->new(
        dom    => $xml,
        status => $status,
        $substatus ? ( sub_status => $substatus) : (),
        issuer => $xpath->findvalue('saml:Issuer', $response),
        id     => $response->getAttribute('ID'),
        in_response_to => $response->getAttribute('InResponseTo'),
        $nodes->size ? (assertions => $nodes) : (),
    );
}

sub to_string {
  my $self = shift;
  return $self->_dom->toString;
}

sub to_assertion {
  my $self = shift;
  my @args = @_;

  if (!$self->has_assertions) {
    croak("There are no assertions found in the response object");
  }

  return Net::SAML2::Protocol::Assertion->new_from_xml(
    @args,
    xml => $self->to_string,
  );
}

1;


__PACKAGE__->meta->make_immutable;

__END__

=head1 DESCRIPTION

=head1 SYNOPSIS

  use Net::SAML2::Object::Response;

  my $var = Net::SAML2::Object::Response->new(...);
  $var->method(...);
