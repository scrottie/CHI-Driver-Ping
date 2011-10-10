
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

CHI::Driver::Ping - Use DBI for cache storage, but access it using the Net::Ping API for MySQL

=head1 SYNOPSIS

 use CHI;

 # Supply a DBI handle

 my $cache = CHI->new( driver => 'Ping', dbh => DBI->connect(...) );

B<ATTENTION>:  This module inherits tests from L<CHI> but I<may> not pass all of L<CHI>'s tests.  
Also, no real functional tests will run unless installed manually as L<cpanm> surpresses prompts for database login information 
for a MySQL database to test against.

=head1 DESCRIPTION

This driver uses a MySQL database table to store the cache.  
It accesses it by way of the Net::Ping API and associated MySQL plug-in:

L<http://yoshinorimatsunobu.blogspot.com/2010/10/using-mysql-as-nosql-story-for.html>

L<https://github.com/ahiguti/Ping-Plugin-for-MySQL>

Why cache things in a database?  Isn't the database what people are trying to
avoid with caches?  

This is often true, but a simple primary key lookup is extremely fast in MySQL and Ping absolutely screams,
avoiding most of the locking that normally happens and completing as many updates/queries as it can at once under the same lock.
Avoiding parsing SQL is also a huge performance boost.

=head1 ATTRIBUTES

=over

=item host

=item read_port

=item write_port

Host and port the MySQL server with the SocketHandler plugin is running on.  The connection is TCP.
Two connections are used, one for reading, one for writing, following the design of L<Net::Ping>.
The write port locks the table even for reads, reportedly.
Default is C<localhost>, C<9998>, and C<9999>.

=item namespace

The namespace you pass in will be appended to the C<table_prefix> and used as a
table name.  That means that if you don't specify a namespace or table_prefix
the cache will be stored in a table called C<chi_Default>.

=item table_prefix

This is the prefix that is used when building a table name.  If you want to
just use the namespace as a literal table name, set this to undef.  Defaults to
C<chi_>.

=item dbh

The DBI handle used to communicate with the db. 

You may pass this handle in one of three forms:

=over

=item *

a regular DBI handle

=item *

a L<DBIx::Connector|DBIx::Connector> object

XXXX doesn't work

=item *

a code reference that will be called each time and is expected to return a DBI
handle, e.g.

    sub { My::Rose::DB->new->dbh }

XXXX doesn't work

=back

The last two options are valuable if your CHI object is going to live for
enough time that a single DBI handle might time out, etc.

=head1 BUGS

=item 0.9

C<t/00load.t> still referenced L<CHI::Handler::DBI> and would fail if it you didn't have it installed.  Fixed in 0.991.

Tests will fail with a message about no tests run unless you run the install manuaully and give it valid DB login info.
Inserted a dummy C<ok()> in there in 0.991.

Should have been specifying CHARSET=ASCII in the create statement to avoid L<http://bugs.mysql.com/bug.php?id=4541>, where utf-8 characters count triple or quadruple or whatever.
Fixed, dubiously, in 0.991.

Huh, turns out that I was developing against L<CHI> 0.36.  Running tests with 0.42 shows me 31 failing tests.

=item 0.991

The database table name was computed from the argument for C<namespace>, but no sanitizing is done on it.  Fixed in 0.992.


=head1 Authors

L<CHI::Driver::Ping> by Scott Walters (scott@slowass.net).

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
  $msg = pack( ICMP_STRUCT . length( $data ), ICMP_ECHO, SUBCODE, $checksum, $self->{"pid"}, $self->{"seq"}, $data );
  $checksum = $self->checksum($msg);
  $msg = pack( ICMP_STRUCT . length( $data ), ICMP_ECHO, SUBCODE, $checksum, $self->{"pid"}, $self->{"seq"}, $data );
  $len_msg = length($msg);
  $saddr = sockaddr_in(ICMP_PORT, inet_aton( $self->ip ) );
  send($self->fh, $msg, ICMP_FLAGS, $saddr); # Send the message
}

sub fetch {

  my $self = shift;
  my $key = shift;

  my $ret = 0;
  my $elapsed_time = 0;

  fcntl($self->fh, F_SETFL, fcntl($self->fh, F_GETFL, 0) | O_NONBLOCK) or die "fcntl: $!";

  my $return_value;

  while(1) {
      my $recv_msg = "";
      my $from_pid = -1;
      my $from_seq = -1;
      my $from_saddr = recv($self->fh, $recv_msg, 1500, ICMP_FLAGS); # sockaddr_in of sender
      if( $! == Errno::EAGAIN ) {
          if( $elapsed_time > 2 ) {
              return; # tired of repeating packets, not in the cache, fell out of the cache, or we've stopped caring
          }
          Time::HiRes::sleep(0.1);
          $elapsed_time += 0.1;
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
              $self->store($key2, $value); 
# warn "found it: $value";
# return ($key, $value); # XXXX
          }
      } elsif( length $recv_msg ) {
        ($from_pid, $from_seq) = unpack("n3", substr($recv_msg, 52, 4)) if length $recv_msg >= 56;
# warn "got not a non ICMP reply";
        next;
      } else {
# warn "no data but that's okay";
          last;
      }
      # $self->{"from_ip"} = $from_ip;
      # $self->{"from_type"} = $from_type;
      # $self->{"from_subcode"} = $from_subcode;
      # if (($from_pid == $self->{"pid"}) && # Does the packet check out?
      #     (! $source_verify || (inet_ntoa($from_ip) eq inet_ntoa($ip))) &&
      #     ($from_seq == $self->{"seq"})) {
      #   if ($from_type == ICMP_ECHOREPLY) {
      #     $ret = 1;
# XXXX
      #   }
      # }
    }
    return $return_value;
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

