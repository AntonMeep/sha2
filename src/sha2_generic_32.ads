pragma Ada_2012;

with Interfaces; use Interfaces;

generic
   type Element is mod <>;
   type Index is range <>;
   type Element_Array is array (Index range <>) of Element;

   Length : Index;

   type State_Array is array (Natural range <>) of Unsigned_32;
   Initial_State : State_Array;
package SHA2_Generic_32 with
   Pure,
   Preelaborate
is
   pragma Compile_Time_Error
     (Element'Modulus /= 256,
      "'Element' type must be mod 2**8, i.e. represent a byte");

   Digest_Length : constant Index := Length;
   Block_Length  : constant Index := 64;

   subtype Digest is Element_Array (0 .. Digest_Length - 1);

   type Context is private;

   function Initialize return Context;
   procedure Initialize (Ctx : out Context);

   procedure Update (Ctx : in out Context; Input : String);
   procedure Update (Ctx : in out Context; Input : Element_Array);

   function Finalize (Ctx : Context) return Digest;
   procedure Finalize (Ctx : Context; Output : out Digest);

   function Hash (Input : String) return Digest;
   function Hash (Input : Element_Array) return Digest;
private
   subtype Block is Element_Array (0 .. Block_Length - 1);

   type Context is record
      State  : State_Array (0 .. 7) := Initial_State;
      Count  : Index                := 0;
      Buffer : Block;
   end record;

   type K_Array is array (Natural range 0 .. 63) of Unsigned_32;

   K : constant K_Array :=
     (16#428a_2f98#, 16#7137_4491#, 16#b5c0_fbcf#, 16#e9b5_dba5#,
      16#3956_c25b#, 16#59f1_11f1#, 16#923f_82a4#, 16#ab1c_5ed5#,
      16#d807_aa98#, 16#1283_5b01#, 16#2431_85be#, 16#550c_7dc3#,
      16#72be_5d74#, 16#80de_b1fe#, 16#9bdc_06a7#, 16#c19b_f174#,
      16#e49b_69c1#, 16#efbe_4786#, 16#0fc1_9dc6#, 16#240c_a1cc#,
      16#2de9_2c6f#, 16#4a74_84aa#, 16#5cb0_a9dc#, 16#76f9_88da#,
      16#983e_5152#, 16#a831_c66d#, 16#b003_27c8#, 16#bf59_7fc7#,
      16#c6e0_0bf3#, 16#d5a7_9147#, 16#06ca_6351#, 16#1429_2967#,
      16#27b7_0a85#, 16#2e1b_2138#, 16#4d2c_6dfc#, 16#5338_0d13#,
      16#650a_7354#, 16#766a_0abb#, 16#81c2_c92e#, 16#9272_2c85#,
      16#a2bf_e8a1#, 16#a81a_664b#, 16#c24b_8b70#, 16#c76c_51a3#,
      16#d192_e819#, 16#d699_0624#, 16#f40e_3585#, 16#106a_a070#,
      16#19a4_c116#, 16#1e37_6c08#, 16#2748_774c#, 16#34b0_bcb5#,
      16#391c_0cb3#, 16#4ed8_aa4a#, 16#5b9c_ca4f#, 16#682e_6ff3#,
      16#748f_82ee#, 16#78a5_636f#, 16#84c8_7814#, 16#8cc7_0208#,
      16#90be_fffa#, 16#a450_6ceb#, 16#bef9_a3f7#, 16#c671_78f2#);

   procedure Transform (Ctx : in out Context);
   pragma Inline (Transform);

   function Ch (X, Y, Z : Unsigned_32) return Unsigned_32;
   function Maj (X, Y, Z : Unsigned_32) return Unsigned_32;
   function Sigma_0 (X : Unsigned_32) return Unsigned_32;
   function Sigma_1 (X : Unsigned_32) return Unsigned_32;
   function S_0 (X : Unsigned_32) return Unsigned_32;
   function S_1 (X : Unsigned_32) return Unsigned_32;
   pragma Inline (Ch, Maj, Sigma_0, Sigma_1, S_0, S_1);
end SHA2_Generic_32;
