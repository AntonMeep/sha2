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

      Length        => 28, State_Array => State_Array_32,
      Initial_State =>
        (16#c105_9ed8#, 16#367c_d507#, 16#3070_dd17#, 16#f70e_5939#,
         16#ffc0_0b31#, 16#6858_1511#, 16#64f9_8fa7#, 16#befa_4fa4#));

   package SHA_256 is new SHA2_Generic_32
     (Element => Element, Index => Index, Element_Array => Element_Array,

      Length        => 32, State_Array => State_Array_32,
      Initial_State =>
        (16#6a09_e667#, 16#bb67_ae85#, 16#3c6e_f372#, 16#a54f_f53a#,
         16#510e_527f#, 16#9b05_688c#, 16#1f83_d9ab#, 16#5be0_cd19#));

   package SHA_384 is new SHA2_Generic_64
     (Element => Element, Index => Index, Element_Array => Element_Array,

      Length        => 48, State_Array => State_Array_64,
      Initial_State =>
        (16#cbbb_9d5d_c105_9ed8#, 16#629a_292a_367c_d507#,
         16#9159_015a_3070_dd17#, 16#152f_ecd8_f70e_5939#,
         16#6733_2667_ffc0_0b31#, 16#8eb4_4a87_6858_1511#,
         16#db0c_2e0d_64f9_8fa7#, 16#47b5_481d_befa_4fa4#));

   package SHA_512 is new SHA2_Generic_64
     (Element => Element, Index => Index, Element_Array => Element_Array,

      Length        => 64, State_Array => State_Array_64,
      Initial_State =>
        (16#6a09_e667_f3bc_c908#, 16#bb67_ae85_84ca_a73b#,
         16#3c6e_f372_fe94_f82b#, 16#a54f_f53a_5f1d_36f1#,
         16#510e_527f_ade6_82d1#, 16#9b05_688c_2b3e_6c1f#,
         16#1f83_d9ab_fb41_bd6b#, 16#5be0_cd19_137e_2179#));

   package SHA_512_224 is new SHA2_Generic_64
     (Element => Element, Index => Index, Element_Array => Element_Array,

      Length        => 28, State_Array => State_Array_64,
      Initial_State =>
        (16#8C3D_37C8_1954_4DA2#, 16#73E1_9966_89DC_D4D6#,
         16#1DFA_B7AE_32FF_9C82#, 16#679D_D514_582F_9FCF#,
         16#0F6D_2B69_7BD4_4DA8#, 16#77E3_6F73_04C4_8942#,
         16#3F9D_85A8_6A1D_36C8#, 16#1112_E6AD_91D6_92A1#));

   package SHA_512_256 is new SHA2_Generic_64
     (Element => Element, Index => Index, Element_Array => Element_Array,

      Length        => 32, State_Array => State_Array_64,
      Initial_State =>
        (16#2231_2194_FC2B_F72C#, 16#9F55_5FA3_C84C_64C2#,
         16#2393_B86B_6F53_B151#, 16#9638_7719_5940_EABD#,
         16#9628_3EE2_A88E_FFE3#, 16#BE5E_1E25_5386_3992#,
         16#2B01_99FC_2C85_B8AA#, 16#0EB7_2DDC_81C5_2CA2#));
end SHA2_Generic;
