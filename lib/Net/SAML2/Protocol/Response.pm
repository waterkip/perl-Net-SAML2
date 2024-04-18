package Net::SAML2::Protocol::Response;

# VERSION

use Moose;
use MooseX::Types::URI qw/ Uri /;
use Net::SAML2::XML::Util qw/ no_comments /;
use XML::LibXML::XPathContext;

with 'Net::SAML2::Role::ProtocolMessage';

# ABSTRACT: SAML2 Response Protocol object

=head1 NAME

Net::SAML2::Protocol::Response - the SAML2 Response object

=head1 SYNOPSIS

  my $response = Net::SAML2::Protocol::Response->new(
    issuer      => $issuer,
    destination => $destination,
    status      => $status,
    response_to => $response_to,
  );

=head1 METHODS

=head2 new( ... )

Constructor. Returns an instance of the Response object.

Arguments:

=over

=item B<issuer>

SP's identity URI

=item B<destination>

IdP's identity URI

=item B<status>

response status

=item B<response_to>

request ID we're responding to

=back

=cut

has 'status'      => (isa => 'Str', is => 'ro', required => 1);
has 'substatus'   => (isa => 'Str', is => 'ro', required => 0);
has 'response_to' => (isa => 'Str', is => 'ro', required => 1);

has _dom => (
    isa      => 'XML::LibXML::Document',
    is       => 'ro',
    required => 1,
    init_arg => 'dom',
);

=head2 new_from_xml( ... )

Create a Response object from the given XML.

Arguments:

=over

=item B<xml>

XML data

=back

=cut

sub new_from_xml {
    my ($class, %args) = @_;

    my $dom = no_comments($args{xml});

    my $xpath = XML::LibXML::XPathContext->new($dom);
    $xpath->registerNs('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
    $xpath->registerNs('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');

    my $self = $class->new(
        dom         => $dom,
        id          => $xpath->findvalue('/samlp:Response/@ID'),
        response_to => $xpath->findvalue('/samlp:Response/@InResponseTo'),
        destination => $xpath->findvalue('/samlp:Response/@Destination'),
        session     => $xpath->findvalue('/samlp:Response/samlp:SessionIndex'),
        issuer      => $xpath->findvalue('/samlp:Response/saml:Issuer'),
        status      => $xpath->findvalue('/samlp:Response/samlp:Status/samlp:StatusCode/@Value'),
        substatus   => $xpath->findvalue('/samlp:Response/samlp:Status/samlp:StatusCode/samlp:StatusCode/@Value'),
    );

    return $self;
}

=head2 as_xml( )

Returns the Response as XML.

=cut

sub as_xml {
    my ($self) = @_;

    return $self->_dom->toString;
}

=head2 success( )

Returns true if the Response's status is Success.

=cut

sub success {
    my ($self) = @_;
    return 1 if $self->status eq $self->status_uri('success');
    return 0;
}

__PACKAGE__->meta->make_immutable;
