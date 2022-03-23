with Interfaces; use Interfaces;

with SHA2_Generic_32;

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

   package SHA_224 is new SHA2_Generic_32
     (Element => Element, Index => Index, Element_Array => Element_Array,

      Digest_Length => 28, H0 => 16#c105_9ed8#, H1 => 16#367c_d507#,
      H2            => 16#3070_dd17#, H3 => 16#f70e_5939#, H4 => 16#ffc0_0b31#,
      H5 => 16#6858_1511#, H6 => 16#64f9_8fa7#, H7 => 16#befa_4fa4#);

   package SHA_256 is new SHA2_Generic_32
     (Element => Element, Index => Index, Element_Array => Element_Array,

      Digest_Length => 32, H0 => 16#6a09_e667#, H1 => 16#bb67_ae85#,
      H2            => 16#3c6e_f372#, H3 => 16#a54f_f53a#, H4 => 16#510e_527f#,
      H5 => 16#9b05_688c#, H6 => 16#1f83_d9ab#, H7 => 16#5be0_cd19#);
end SHA2_Generic;
