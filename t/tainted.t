#!perl -T

use Test::More tests=>4;

BEGIN { use_ok( 'Test::Taint' ); }

my @keys = keys %ENV;
my $key = shift @keys;

taint_checking_ok();
ok( tainted($ENV{$key}), "\$ENV{$key} is tainted" );

my $foo = 43;
ok( !tainted($foo), "43 is not tainted" );

