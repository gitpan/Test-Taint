#!perl -T

use Test::More;
use Test::Taint tests=>7;

taint_checking_ok();

my $foo = 43;
untainted_ok( $foo, 'Starts clean' );
taint($foo);
tainted_ok( $foo, 'Gets dirty' );
$foo =~ /(\d+)/;
$foo = $1;
untainted_ok( $foo, 'Reclean' );

my $bar = 'bar';
untainted_ok( $bar, 'Starts clean' );
taint($bar);
tainted_ok( $bar, 'Gets dirty' );
is($bar, 'bar', 'String value stays the same');
