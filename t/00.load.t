# $Id: 00.load.t,v 1.1.1.1 2004/02/04 03:46:16 andy Exp $

use Test::More tests => 1;

use_ok( 'Test::Taint' );

diag( "Testing Test::Taint $Test::Taint::VERSION" );
