
package CHI::Driver::Ping;

use strict;
use warnings;

use Moose;
use Moose::Util::TypeConstraints;

use Fcntl;
use Errno;
use FileHandle;
use Socket;
use Time::HiRes;

use Carp 'croak';

extends 'CHI::Driver';

use 5.006;
our $VERSION = '0.00000001';

use constant ICMP_ECHOREPLY   => 0; # ICMP packet types
use constant ICMP_UNREACHABLE => 3; # ICMP packet types
use constant ICMP_ECHO        => 8;
use constant ICMP_STRUCT      => "C2 n3 A"; # Structure of a minimal ICMP packet
use constant SUBCODE          => 0; # No ICMP subcode for ECHO and ECHOREPLY
use constant ICMP_FLAGS       => 0; # No special flags for send or recv
use constant ICMP_PORT        => 0; # No port with ICMP

=head1 NAME

CHI::Driver::Ping - Cache data in the Ether.


=head1 SYNOPSIS

 use CHI;

 system 'sysctl', '-w', 'net.ipv4.icmp_ratelimit=100000';

 my $cache = CHI->new( driver => 'Ping', ip => 74.125.73.105 );

=head1 DESCRIPTION

Tap into the Ether.  Optimize for CPU or storage?  Fuck that.

Inspired by Delay Line Memory, L<http://en.wikipedia.org/wiki/Delay_line_memory>, 
this modules stores data by transmitting it through a medium known to have a
delay and waiting for it to come back again, whereupon it both returns it and
retransmits it out.
It seems rather pointless and silly to bother with spinning metal oxide 
covered platters or billions of tiny capacitors when data can be stored
in the air between the Earth and sattelites, in ordinary copper wire, 
and in easy to extrude lengths of glass fiber.

=head1 ATTRIBUTES

=over

=item ip

Who to send all of the ICMP ECHOPINGs to.

=item namespace

The namespace you pass in will be appended to the C<table_prefix> and used as a
table name.  That means that if you don't specify a namespace or table_prefix
the cache will be stored in a table called C<chi_Default>.

=back

=head1 TODO

CIDR block of hosts to use, or a list, or something.  Even better, scan the network
for hosts that are up and build this dynamically.  For extra points, find hosts with
a lot of hops to them.

=head1 BUGS

=item 0.00000001

Initial; github dev version.


=head1 Authors

L<CHI::Driver::Ping> by Scott Walters (scott@slowass.net) with suggestions from 
Brock Wilcox (awwaiid@thelackthereof.org).

=head1 COPYRIGHT & LICENSE

Copyright (c) Scott Walters (scrottie) 2011

This program is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.

=cut

has 'table_prefix' => ( is => 'rw', isa => 'Str', default => 'chi_', );

has 'proto_num' => ( is => 'rw' );

has 'pid' => ( is => 'rw' );

has 'fh' => ( is => 'rw' );

has 'seq' => ( is => 'rw', default => 0 );

has 'ip' => ( is => 'rw', default => '127.0.0.1' );

__PACKAGE__->meta->make_immutable;

sub BUILD {
    my $self = shift;
    croak("icmp ping requires root privilege") if ($> and $^O ne 'VMS' and $^O ne 'cygwin');
    $self->proto_num( (getprotobyname('icmp'))[2] || croak("Can't get icmp protocol by name") );
    $self->pid( $$ & 0xffff );           # Save lower 16 bits of pid
    $self->fh( FileHandle->new() );
    socket($self->fh, PF_INET, SOCK_RAW, $self->proto_num) or croak "icmp socket error - $!";
}

sub remove {
    my ( $self, $key, ) = @_;
    return;
}

sub clear { 
    my $self = shift;
    # my $sth = $dbh->prepare_cached( qq{ DELETE FROM $table } ) or croak $dbh->errstr;
    return;
}

sub get_keys {
    my ( $self ) = @_;
}

sub get_namespaces { croak 'not supported' }

sub store {

  my $self = shift;
  my $key = shift;
  my $value = shift;

  my $ip = $self->ip();

# warn "ip: $ip";

  my ($saddr,             # sockaddr_in with port and ip
      $msg,               # ICMP packet to send
      $len_msg,           # Length of $msg
      $nfound,            # Number of ready filehandles found
      $ret,               # Return value
      $recv_msg,          # Received message including IP header
      );

  my $data = join '', $key, chr(0), $value;

  $self->seq( ( $self->seq() + 1) % 65536 );   # Increment sequence
  my $checksum = 0; 
  $msg = pack( ICMP_STRUCT . length( $data ), ICMP_ECHO, SUBCODE, $checksum, $self->pid, $self->seq, $data );
  $checksum = $self->checksum($msg);
  $msg = pack( ICMP_STRUCT . length( $data ), ICMP_ECHO, SUBCODE, $checksum, $self->pid, $self->seq, $data );
  $len_msg = length($msg);
  $saddr = sockaddr_in(ICMP_PORT, inet_aton( $self->ip ) );
  send($self->fh, $msg, ICMP_FLAGS, $saddr); # Send the message
}

sub fetch {

  local $SIG{USR1} = sub { use Carp; Carp::cluck "USR1"; };

  my $self = shift;
  my $key = shift;
  my $mode = shift;

  my $delete_mode = 1 if $mode eq 'delete';  # don't retransmit this packet once we see it

  my $ret = 0;

  fcntl($self->fh, F_SETFL, fcntl($self->fh, F_GETFL, 0) | O_NONBLOCK) or die "fcntl: $!";

  my $start_time = Time::HiRes::time;
# warn "start_time $start_time";
  my $return_value;

  while(1) {
      return if Time::HiRes::time - $start_time > 2; # <------ here is also where we exit, in failure
      my $recv_msg = "";
      my $from_pid = -1;
      my $from_seq = -1;
      my $from_saddr = recv($self->fh, $recv_msg, 1500, ICMP_FLAGS); # sockaddr_in of sender
      if( $! == Errno::EAGAIN ) {
          Time::HiRes::sleep(0.1);
          next;
      }
      my $from_port;         # Port packet was sent from
      my $from_ip;           # Packed IP of sender
      ($from_port, $from_ip) = sockaddr_in($from_saddr);
      (my $from_type, my $from_subcode) = unpack("C2", substr($recv_msg, 20, 2));
      if ($from_type == ICMP_ECHOREPLY) {
          ($from_pid, $from_seq) = unpack("n3", substr($recv_msg, 24, 4, ''));
          if( length $recv_msg >= 28 ) {
# warn "raw message: $recv_msg";
              substr $recv_msg, 0, 24, '';
              my $i = index $recv_msg, chr(0);
              my $key2 = substr $recv_msg, 0, $i;
              my $value = substr $recv_msg, $i+1;
              $return_value = $value if $key eq $key2;  # don't return yet but remember what to return
              $self->store($key2, $value) unless $delete_mode; 
              return $return_value if $key eq $key2; # <---------- here is where we exit this
# warn "found it: $value";
# return ($key, $value); # XXXX
          }
      }
    }
}

sub checksum {

  my ($class,
      $msg            # The message to checksum
      ) = @_;
  my ($len_msg,       # Length of the message
      $num_short,     # The number of short words in the message
      $short,         # One short word
      $chk            # The checksum
      );
      
  $len_msg = length($msg);
  $num_short = int($len_msg / 2);
  $chk = 0;
  foreach $short (unpack("n$num_short", $msg)) 
  {   
    $chk += $short;       
  }                                           # Add the odd byte in
  $chk += (unpack("C", substr($msg, $len_msg - 1, 1)) << 8) if $len_msg % 2;
  $chk = ($chk >> 16) + ($chk & 0xffff);      # Fold high into low
  return(~(($chk >> 16) + $chk) & 0xffff);    # Again and complement
}


    
1;

__END__

