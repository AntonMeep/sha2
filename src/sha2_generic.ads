with Interfaces; use Interfaces;

with SHA2_Generic_32;
with SHA2_Generic_64;

generic
   type Element is mod <>;
   type Index is range <>;
   type Element_Array is array (Index range <>) of Element;
package SHA2_Generic with
   Pure,
   Preelaborate
is
   pragma Compile_Time_Error
     (Element'Modulus /= 256,
      "'Element' type must be mod 2**8, i.e. represent a byte");

   type State_Array_32 is array (Natural range <>) of Unsigned_32;
   type State_Array_64 is array (Natural range <>) of Unsigned_64;

   package SHA_224 is new SHA2_Generic_32
     (Element => Element, Index => Index, Element_Array => Element_Array,

      Digest_Length => 28, State_Array => State_Array_32,
      Initial_State =>
        (16#c105_9ed8#, 16#367c_d507#, 16#3070_dd17#, 16#f70e_5939#,
         16#ffc0_0b31#, 16#6858_1511#, 16#64f9_8fa7#, 16#befa_4fa4#));

   package SHA_256 is new SHA2_Generic_32
     (Element => Element, Index => Index, Element_Array => Element_Array,

      Digest_Length => 32, State_Array => State_Array_32,
      Initial_State =>
        (16#6a09_e667#, 16#bb67_ae85#, 16#3c6e_f372#, 16#a54f_f53a#,
         16#510e_527f#, 16#9b05_688c#, 16#1f83_d9ab#, 16#5be0_cd19#));

   package SHA_512 is new SHA2_Generic_64
     (Element => Element, Index => Index, Element_Array => Element_Array,

      Digest_Length => 64, State_Array => State_Array_64,
      Initial_State =>
        (16#6a09_e667_f3bc_c908#, 16#bb67_ae85_84ca_a73b#,
         16#3c6e_f372_fe94_f82b#, 16#a54f_f53a_5f1d_36f1#,
         16#510e_527f_ade6_82d1#, 16#9b05_688c_2b3e_6c1f#,
         16#1f83_d9ab_fb41_bd6b#, 16#5be0_cd19_137e_2179#));
end SHA2_Generic;
