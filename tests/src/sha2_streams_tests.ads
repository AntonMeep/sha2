with AUnit.Test_Fixtures;
with AUnit.Test_Suites;

package SHA2_Streams_Tests is
   function Suite return AUnit.Test_Suites.Access_Test_Suite;
private
   type Fixture is new AUnit.Test_Fixtures.Test_Fixture with null record;

   procedure SHA2_224_Test (Object : in out Fixture);
   procedure SHA2_256_Test (Object : in out Fixture);
   procedure SHA2_512_Test (Object : in out Fixture);
end SHA2_Streams_Tests;
