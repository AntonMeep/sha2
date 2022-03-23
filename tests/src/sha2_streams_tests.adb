pragma Ada_2012;

with AUnit.Assertions; use AUnit.Assertions;
with AUnit.Test_Caller;

with Ada.Streams; use Ada.Streams;
with SHA2;

package body SHA2_Streams_Tests is
   package Caller is new AUnit.Test_Caller (Fixture);

   Test_Suite : aliased AUnit.Test_Suites.Test_Suite;

   function Suite return AUnit.Test_Suites.Access_Test_Suite is
      Name : constant String := "[SHA2 - Ada.Streams] ";
   begin
      Test_Suite.Add_Test
        (Caller.Create (Name & "SHA_224()", SHA2_224_Test'Access));
      Test_Suite.Add_Test
        (Caller.Create (Name & "SHA_256()", SHA2_256_Test'Access));
      Test_Suite.Add_Test
        (Caller.Create (Name & "SHA_512()", SHA2_512_Test'Access));

      return Test_Suite'Access;
   end Suite;

   procedure SHA2_224_Test (Object : in out Fixture) is
      use SHA2.SHA_224;
   begin
      Assert
        (Hash ("abc") =
         (16#23#, 16#09#, 16#7d#, 16#22#, 16#34#, 16#05#, 16#d8#, 16#22#,
          16#86#, 16#42#, 16#a4#, 16#77#, 16#bd#, 16#a2#, 16#55#, 16#b3#,
          16#2a#, 16#ad#, 16#bc#, 16#e4#, 16#bd#, 16#a0#, 16#b3#, 16#f7#,
          16#e3#, 16#6c#, 16#9d#, 16#a7#),
         "Hash(`abc`)");
      Assert
        (Hash ("") =
         (16#d1#, 16#4a#, 16#02#, 16#8c#, 16#2a#, 16#3a#, 16#2b#, 16#c9#,
          16#47#, 16#61#, 16#02#, 16#bb#, 16#28#, 16#82#, 16#34#, 16#c4#,
          16#15#, 16#a2#, 16#b0#, 16#1f#, 16#82#, 16#8e#, 16#a6#, 16#2a#,
          16#c5#, 16#b3#, 16#e4#, 16#2f#),
         "Hash(``) empty string input");
      Assert
        (Hash ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") =
         (16#75#, 16#38#, 16#8b#, 16#16#, 16#51#, 16#27#, 16#76#, 16#cc#,
          16#5d#, 16#ba#, 16#5d#, 16#a1#, 16#fd#, 16#89#, 16#01#, 16#50#,
          16#b0#, 16#c6#, 16#45#, 16#5c#, 16#b4#, 16#f5#, 16#8b#, 16#19#,
          16#52#, 16#52#, 16#25#, 16#25#),
         "Hash(`abcdbcde...`) 448 bits of input");
      Assert
        (Hash
           ("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno" &
            "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu") =
         (16#c9#, 16#7c#, 16#a9#, 16#a5#, 16#59#, 16#85#, 16#0c#, 16#e9#,
          16#7a#, 16#04#, 16#a9#, 16#6d#, 16#ef#, 16#6d#, 16#99#, 16#a9#,
          16#e0#, 16#e0#, 16#e2#, 16#ab#, 16#14#, 16#e6#, 16#b8#, 16#df#,
          16#26#, 16#5f#, 16#c0#, 16#b3#),
         "Hash(`abcdbcde...`) 896 bits of input");
   end SHA2_224_Test;

   procedure SHA2_256_Test (Object : in out Fixture) is
      use SHA2.SHA_256;
   begin
      Assert
        (Hash ("abc") =
         (16#ba#, 16#78#, 16#16#, 16#bf#, 16#8f#, 16#01#, 16#cf#, 16#ea#,
          16#41#, 16#41#, 16#40#, 16#de#, 16#5d#, 16#ae#, 16#22#, 16#23#,
          16#b0#, 16#03#, 16#61#, 16#a3#, 16#96#, 16#17#, 16#7a#, 16#9c#,
          16#b4#, 16#10#, 16#ff#, 16#61#, 16#f2#, 16#00#, 16#15#, 16#ad#),
         "Hash(`abc`)");
      Assert
        (Hash ("") =
         (16#e3#, 16#b0#, 16#c4#, 16#42#, 16#98#, 16#fc#, 16#1c#, 16#14#,
          16#9a#, 16#fb#, 16#f4#, 16#c8#, 16#99#, 16#6f#, 16#b9#, 16#24#,
          16#27#, 16#ae#, 16#41#, 16#e4#, 16#64#, 16#9b#, 16#93#, 16#4c#,
          16#a4#, 16#95#, 16#99#, 16#1b#, 16#78#, 16#52#, 16#b8#, 16#55#),
         "Hash(``) empty string input");
      Assert
        (Hash ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") =
         (16#24#, 16#8d#, 16#6a#, 16#61#, 16#d2#, 16#06#, 16#38#, 16#b8#,
          16#e5#, 16#c0#, 16#26#, 16#93#, 16#0c#, 16#3e#, 16#60#, 16#39#,
          16#a3#, 16#3c#, 16#e4#, 16#59#, 16#64#, 16#ff#, 16#21#, 16#67#,
          16#f6#, 16#ec#, 16#ed#, 16#d4#, 16#19#, 16#db#, 16#06#, 16#c1#),
         "Hash(`abcdbcde...`) 448 bits of input");
      Assert
        (Hash
           ("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno" &
            "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu") =
         (16#cf#, 16#5b#, 16#16#, 16#a7#, 16#78#, 16#af#, 16#83#, 16#80#,
          16#03#, 16#6c#, 16#e5#, 16#9e#, 16#7b#, 16#04#, 16#92#, 16#37#,
          16#0b#, 16#24#, 16#9b#, 16#11#, 16#e8#, 16#f0#, 16#7a#, 16#51#,
          16#af#, 16#ac#, 16#45#, 16#03#, 16#7a#, 16#fe#, 16#e9#, 16#d1#),
         "Hash(`abcdbcde...`) 896 bits of input");
   end SHA2_256_Test;

   procedure SHA2_512_Test (Object : in out Fixture) is
      use SHA2.SHA_512;
   begin
      Assert
        (Hash ("abc") =
         (16#dd#, 16#af#, 16#35#, 16#a1#, 16#93#, 16#61#, 16#7a#, 16#ba#,
          16#cc#, 16#41#, 16#73#, 16#49#, 16#ae#, 16#20#, 16#41#, 16#31#,
          16#12#, 16#e6#, 16#fa#, 16#4e#, 16#89#, 16#a9#, 16#7e#, 16#a2#,
          16#0a#, 16#9e#, 16#ee#, 16#e6#, 16#4b#, 16#55#, 16#d3#, 16#9a#,
          16#21#, 16#92#, 16#99#, 16#2a#, 16#27#, 16#4f#, 16#c1#, 16#a8#,
          16#36#, 16#ba#, 16#3c#, 16#23#, 16#a3#, 16#fe#, 16#eb#, 16#bd#,
          16#45#, 16#4d#, 16#44#, 16#23#, 16#64#, 16#3c#, 16#e8#, 16#0e#,
          16#2a#, 16#9a#, 16#c9#, 16#4f#, 16#a5#, 16#4c#, 16#a4#, 16#9f#),
         "Hash(`abc`)");
      Assert
        (Hash ("") =
         (16#cf#, 16#83#, 16#e1#, 16#35#, 16#7e#, 16#ef#, 16#b8#, 16#bd#,
          16#f1#, 16#54#, 16#28#, 16#50#, 16#d6#, 16#6d#, 16#80#, 16#07#,
          16#d6#, 16#20#, 16#e4#, 16#05#, 16#0b#, 16#57#, 16#15#, 16#dc#,
          16#83#, 16#f4#, 16#a9#, 16#21#, 16#d3#, 16#6c#, 16#e9#, 16#ce#,
          16#47#, 16#d0#, 16#d1#, 16#3c#, 16#5d#, 16#85#, 16#f2#, 16#b0#,
          16#ff#, 16#83#, 16#18#, 16#d2#, 16#87#, 16#7e#, 16#ec#, 16#2f#,
          16#63#, 16#b9#, 16#31#, 16#bd#, 16#47#, 16#41#, 16#7a#, 16#81#,
          16#a5#, 16#38#, 16#32#, 16#7a#, 16#f9#, 16#27#, 16#da#, 16#3e#),
         "Hash(``) empty string input");
      Assert
        (Hash ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") =
         (16#20#, 16#4a#, 16#8f#, 16#c6#, 16#dd#, 16#a8#, 16#2f#, 16#0a#,
          16#0c#, 16#ed#, 16#7b#, 16#eb#, 16#8e#, 16#08#, 16#a4#, 16#16#,
          16#57#, 16#c1#, 16#6e#, 16#f4#, 16#68#, 16#b2#, 16#28#, 16#a8#,
          16#27#, 16#9b#, 16#e3#, 16#31#, 16#a7#, 16#03#, 16#c3#, 16#35#,
          16#96#, 16#fd#, 16#15#, 16#c1#, 16#3b#, 16#1b#, 16#07#, 16#f9#,
          16#aa#, 16#1d#, 16#3b#, 16#ea#, 16#57#, 16#78#, 16#9c#, 16#a0#,
          16#31#, 16#ad#, 16#85#, 16#c7#, 16#a7#, 16#1d#, 16#d7#, 16#03#,
          16#54#, 16#ec#, 16#63#, 16#12#, 16#38#, 16#ca#, 16#34#, 16#45#),
         "Hash(`abcdbcde...`) 448 bits of input");
      Assert
        (Hash
           ("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno" &
            "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu") =
         (16#8e#, 16#95#, 16#9b#, 16#75#, 16#da#, 16#e3#, 16#13#, 16#da#,
          16#8c#, 16#f4#, 16#f7#, 16#28#, 16#14#, 16#fc#, 16#14#, 16#3f#,
          16#8f#, 16#77#, 16#79#, 16#c6#, 16#eb#, 16#9f#, 16#7f#, 16#a1#,
          16#72#, 16#99#, 16#ae#, 16#ad#, 16#b6#, 16#88#, 16#90#, 16#18#,
          16#50#, 16#1d#, 16#28#, 16#9e#, 16#49#, 16#00#, 16#f7#, 16#e4#,
          16#33#, 16#1b#, 16#99#, 16#de#, 16#c4#, 16#b5#, 16#43#, 16#3a#,
          16#c7#, 16#d3#, 16#29#, 16#ee#, 16#b6#, 16#dd#, 16#26#, 16#54#,
          16#5e#, 16#96#, 16#e5#, 16#5b#, 16#87#, 16#4b#, 16#e9#, 16#09#),
         "Hash(`abcdbcde...`) 896 bits of input");
   end SHA2_512_Test;
end SHA2_Streams_Tests;
