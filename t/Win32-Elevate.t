# Before 'make install' is performed this script should be runnable with
# 'make test'. After 'make install' it should work as 'perl Win32-Elevate.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use strict;
use warnings;

#use Win32;

use Test::More tests => 9;
BEGIN { use_ok('Win32::Elevate') };

#########################

is( $^O, 'MSWin32', 'Check for Win32 platform');

# ToSystem()
is( Win32::Elevate::ToSystem(), 0, "Elevate to system credentials; Error: $^E" );
like( Win32::Elevate::LoginName(), '/SYSTEM$/', "Have system credentials" );

# RevertToSelf() after SYSTEM elevation
isnt( Win32::Elevate::RevertToSelf(), 0, "RevertToSelf; Error: $^E" );
unlike( Win32::Elevate::LoginName(), '/SYSTEM$/', "Don't have system credentials" );

# ToTI()
is( Win32::Elevate::ToTI(), 0, "Elevate to trusted installer credentials; Error: $^E" );

# RevertToSelf() after TI elevation
isnt( Win32::Elevate::RevertToSelf(), 0, "RevertToSelf; Error: $^E" );
unlike( Win32::Elevate::LoginName(), '/SYSTEM$/', "Don't have system credentials" );

