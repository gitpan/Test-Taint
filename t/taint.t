#!perl -T

use Test::Taint tests=>4;

taint_checking_ok();

my $foo = 43;
untainted_ok( $foo, 'Starts clean' );
taint($foo);
tainted_ok( $foo, 'Gets dirty' );
$foo =~ /(\d+)/;
$foo = $1;
untainted_ok( $foo, 'Reclean' );
