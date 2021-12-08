use strict;
use warnings;
package Net::SAML2::Protocol::LogoutResponse;
use Moose;
use MooseX::Types::URI qw/ Uri /;
use Net::SAML2::XML::Util qw/ no_comments /;

with 'Net::SAML2::Role::ProtocolMessage';

# ABSTRACT: SAML2 LogoutResponse Protocol object

our $VERSION = '0.49';

=head1 NAME

Net::SAML2::Protocol::LogoutResponse - the SAML2 LogoutResponse object

=head1 SYNOPSIS

  my $logout_req = Net::SAML2::Protocol::LogoutResponse->new(
    issuer      => $issuer,
    destination => $destination,
    status      => $status,
    response_to => $response_to,
  );

=head1 METHODS

=head2 new( ... )

Constructor. Returns an instance of the LogoutResponse object.

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

=head2 new_from_xml( ... )

Create a LogoutResponse object from the given XML.

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
        id          => $xpath->findvalue('/samlp:LogoutResponse/@ID'),
        response_to => $xpath->findvalue('/samlp:LogoutResponse/@InResponseTo'),
        destination => $xpath->findvalue('/samlp:LogoutResponse/@Destination'),
        session     => $xpath->findvalue('/samlp:LogoutResponse/samlp:SessionIndex'),
        issuer      => $xpath->findvalue('/samlp:LogoutResponse/saml:Issuer'),
        status      => $xpath->findvalue('/samlp:LogoutResponse/samlp:Status/samlp:StatusCode/@Value'),
        substatus   => $xpath->findvalue('/samlp:LogoutResponse/samlp:Status/samlp:StatusCode/samlp:StatusCode/@Value'),
    );

    return $self;
}

=head2 as_xml( )

Returns the LogoutResponse as XML.

=cut

sub as_xml {
    my ($self) = @_;

    my $x = XML::Generator->new(':pretty');
    my $saml  = ['saml' => 'urn:oasis:names:tc:SAML:2.0:assertion'];
    my $samlp = ['samlp' => 'urn:oasis:names:tc:SAML:2.0:protocol'];

    $x->xml(
        $x->LogoutResponse(
            $samlp,
            { ID => $self->id,
              Version => '2.0',
              IssueInstant => $self->issue_instant,
              Destination => $self->destination,
              InResponseTo => $self->response_to },
            $x->Issuer(
                $saml,
                $self->issuer,
            ),
            $x->Status(
                $samlp,
                $x->StatusCode(
                    $samlp,
                    { Value => $self->status },
                )
            )
        )
    );
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
