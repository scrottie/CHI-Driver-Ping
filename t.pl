
use strict;
use warnings;

use lib "lib";

use CHI;
use CHI::Driver::Ping;

$SIG{__DIE__} = sub { use Carp; Carp::confess $_[0] };

my $cache = CHI->new( driver => 'Ping', ip => '70.87.222.98', );

$cache->store('testkey', 'testvalue');
$cache->store('otherkey', 'otherstuff');

my $v;

while(1) {

    ($v) = $cache->fetch('testkey');
    if( $v and $v eq 'testvalue' ) {
        warn 'testkey=testvalue round trip 1';
    } else {
        die "wrong value: $v" if $v;
        warn "lost packet" if ! $v;
    }

    ($v) = $cache->fetch('testkey');
    if( $v and $v eq 'testvalue' ) {
        warn 'testkey=testvalue round trip 2';
    } else {
        die "wrong value: $v" if $v;
        warn "lost packet" if ! $v;
    }

    ($v) = $cache->fetch('otherkey');
    if( $v and $v eq 'otherstuff' ) {
        warn 'otherkey=otherstuff round trip 1';
    } else {
        die "wrong value: $v" if $v;
        warn "lost packet" if ! $v;
    }
}

