#!perl -w

# Note the lack of -T there

use Test::Taint tests=>5;
use Test::More;

ok( !taint_checking(), "Taint checking is off" );

my $foo = 43;
untainted_ok( $foo, 'Starts clean' );
taint($foo);
untainted_ok( $foo, 'Stays clean' );
untainted_ok( $Test::Taint::TAINT );
untainted_ok( $Test::Taint::TAINT0 );
