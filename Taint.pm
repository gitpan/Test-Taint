package Test::Taint;

=head1 NAME

Test::Taint - Tools to test taintedness

=head1 VERSION

Version 1.00

    $Header: /home/cvs/test-taint/Taint.pm,v 1.11 2004/03/15 02:12:00 andy Exp $

=cut

use vars qw( $VERSION );
$VERSION = "1.00";

=head1 SYNOPSIS

    taint_checking_ok();        # We have to have taint checking on
    my $id = "deadbeef";        # Dummy session ID
    taint( $id );               # Simulate it coming in from the web
    tainted_ok( $id );
    $id = validate_id( $id );   # Your routine to check the $id
    untainted_ok( $id );        # Did it come back clean?
    ok( defined $id );

=head1 DESCRIPTION

Tainted data is data that comes from an unsafe source, such as the
command line, or, in the case of web apps, any GET or POST transactions.
Read the L<perlsec> man page for details on why tainted data is bad,
and how to untaint the data.

When you're writing unit tests for code that deals with tainted data,
you'll want to have a way to provide tainted data for your routines to
handle, and easy ways to check and report on the taintedness of your data,
in standard L<Test::More> style.

=cut

use strict;
use warnings;

use DynaLoader;
use Test::Builder;
use vars qw( $TAINT );

my $Test = Test::Builder->new;

use vars qw( @EXPORT @ISA );
@EXPORT = qw( taint tainted tainted_ok untainted_ok taint_checking taint_checking_ok );
@ISA = qw(DynaLoader);

bootstrap Test::Taint $VERSION;

sub import {
    my $self = shift;
    my $caller = caller;
    no strict 'refs';
    for my $sub ( @EXPORT ) {
        *{$caller.'::'.$sub} = \&$sub;
    }
    $Test->exported_to($caller);
    $Test->plan(@_);
}

=head1 C<Test::More>-style Functions

All the C<xxx_ok()> functions work like standard C<Test::More>-style
functions, where the last parm is an optional message, it outputs ok or
not ok, and returns a boolean telling if the test passed.

=head2 taint_checking_ok( [$message] )

L<Test::More>-style test that taint checking is on.  This should probably
be the first thing in any F<*.t> file that deals with taintedness.

=cut

sub taint_checking_ok {
    my $msg = @_ ? shift : "Taint checking is on";

    my $ok = taint_checking();
    $Test->ok( $ok, $msg );

    return $ok;
} # tainted_ok

=head2 tainted_ok( $var [, $message ] )

Checks that I<$var> is tainted.

    tainted_ok( $ENV{FOO} );

=cut

sub tainted_ok {
    my $var = shift;
    my $msg = shift;
    my $ok = tainted( $var );
    $Test->ok( $ok, $msg );

    return $ok;
} # tainted_ok

=head2 untainted_ok( $var [, $message ] )

Checks that I<$var> is not tainted.

    my $foo = my_validate( $ENV{FOO} );
    untainted_ok( $foo );

=cut

sub untainted_ok {
    my $var = shift;
    my $msg = shift;

    my $ok = !tainted( $var );
    $Test->ok( $ok, $msg );

    return $ok;
} # tainted_ok

=head1 Helper Functions

These are all helper functions.  Most are wrapped by an C<xxx_ok()>
counterpart, except for C<taint> which actually does something, instead
of just reporting it.

=head2 taint_checking()

Returns true if taint checking is enabled via the -T flag.

=cut

sub taint_checking() {
    return tainted( $Test::Taint::TAINT );
}

=head2 tainted( I<$var> )

Returns boolean saying if C<$var> is tainted.

=cut

sub tainted {
    no warnings;

    return !eval { join("",@_), kill 0; 1 };
}

=head2 taint( @list )

Marks each (apparently) taintable argument in I<@list> as being tainted.

References can be tainted like any other scalar, but it doesn't make
sense to, so they will B<not> be tainted by this function.

Some C<tie>d and magical variables may fail to be tainted by this routine,
try as it may.)

=cut

sub taint {
    local $_;

    for ( @_ ) {
        _taint($_) unless ref;
    }
}

# _taint() is an external function in Taint.xs

BEGIN {
    MAKE_SOME_TAINT: {
        # Somehow we need to get some taintedness into $Test::Taint::TAINT
        # Let's try the easy way first. Either of these should be
        # tainted, unless somebody has untainted them, so this
        # will almost always work on the first try.
        # (Unless, of course, taint checking has been turned off!)
        $TAINT = substr("$0$^X", 0, 0);
        last if tainted $TAINT;

        # Let's try again. Maybe somebody cleaned those.
        $TAINT = substr(join("", @ARGV, %ENV), 0, 0);
        last if tainted $TAINT;

        # If those don't work, go try to open some file from some unsafe
        # source and get data from them.  That data is tainted.
        # (Yes, even reading from /dev/null works!)
        local(*FOO);
        for ( qw(/dev/null / . ..), values %INC, $0, $^X ) {
            if ( open FOO, $_ ) {
                my $data;
                if ( defined sysread FOO, $data, 1 ) {
                    $TAINT = substr( $data, 0, 0 );
                    last if tainted $TAINT;
                }
            }
        }
        close FOO;
    }

    # Sanity check
    die "Our taintbrush should have zero length!" if length $TAINT;
}


=head1 AUTHOR

Written by Andy Lester, C<< <andy@petdance.com> >>.

=head1 COPYRIGHT

Copyright 2004, Andy Lester, All Rights Reserved.

You may use, modify, and distribute this package under the
same terms as Perl itself.

=cut

1;
