# Before 'make install' is performed this script should be runnable with
# 'make test'. After 'make install' it should work as 'perl Win32-Elevate.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use strict;
use warnings;

use Win32;

use Test::More tests => 7;
BEGIN { use_ok('Win32::Elevate') };

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.

is( $^O, 'MSWin32', 'Check for Win32 platform');

# ToSystem()
is( Win32::Elevate::ToSystem(), 0, "Elevate to system credentials; Error: $^E" );
like( Win32::LoginName(), '/SYSTEM$/', "Have system credentials" );

#sleep(30);

# DeElevate()
isnt( Win32::Elevate::DeElevate(), 0, "De-elevate; Error: $^E" );
unlike( Win32::LoginName(), '/SYSTEM/', "Don't have system credentials" );

#sleep(30);

# ToTI(); this one fails currently
is( Win32::Elevate::ToTI(), 0, "Elevate to trusted installer credentials; Error: $^E" );



