package CHI::Driver::Ping::t::CHIDriverTests::Ping;

use Module::Load::Conditional qw(can_load);
use Test::More;
use base qw(CHI::t::Driver);

use strict;
use warnings;

sub testing_driver_class { 'CHI::Driver::Ping' }

sub required_modules { 
    return { };
}

sub runtests {
    my $class = shift;
    my %opts = @_;
    $class->SUPER::runtests();
}

sub cleanup : Tests( shutdown ) {
    # unlink 't/dbfile.db';
}

# ---------------------------------------------------------------------------

# package CHI::Driver::Ping::t::CHIDriverTests::Base;

sub supports_get_namespaces { 0 }

sub SKIP_CLASS {
    my $class = shift;
    return 0;
}
 
#sub new_cache_options {
#    my $self = shift;
#
#    return (
#        $self->SUPER::new_cache_options(),
#    );
#}

1;
