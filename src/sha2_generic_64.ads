pragma Ada_2012;

with Interfaces; use Interfaces;

generic
   type Element is mod <>;
   type Index is range <>;
   type Element_Array is array (Index range <>) of Element;

   Length : Index;

   type State_Array is array (Natural range <>) of Unsigned_64;
   Initial_State : State_Array;
package SHA2_Generic_64 with
   Pure,
   Preelaborate
is
   pragma Compile_Time_Error
     (Element'Modulus /= 256,
      "'Element' type must be mod 2**8, i.e. represent a byte");

   Digest_Length : constant Index := Length;
   Block_Length  : constant Index := 128;

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

   type K_Array is array (Natural range 0 .. 79) of Unsigned_64;

   K : constant K_Array :=
     (16#428a_2f98_d728_ae22#, 16#7137_4491_23ef_65cd#,
      16#b5c0_fbcf_ec4d_3b2f#, 16#e9b5_dba5_8189_dbbc#,
      16#3956_c25b_f348_b538#, 16#59f1_11f1_b605_d019#,
      16#923f_82a4_af19_4f9b#, 16#ab1c_5ed5_da6d_8118#,
      16#d807_aa98_a303_0242#, 16#1283_5b01_4570_6fbe#,
      16#2431_85be_4ee4_b28c#, 16#550c_7dc3_d5ff_b4e2#,
      16#72be_5d74_f27b_896f#, 16#80de_b1fe_3b16_96b1#,
      16#9bdc_06a7_25c7_1235#, 16#c19b_f174_cf69_2694#,
      16#e49b_69c1_9ef1_4ad2#, 16#efbe_4786_384f_25e3#,
      16#0fc1_9dc6_8b8c_d5b5#, 16#240c_a1cc_77ac_9c65#,
      16#2de9_2c6f_592b_0275#, 16#4a74_84aa_6ea6_e483#,
      16#5cb0_a9dc_bd41_fbd4#, 16#76f9_88da_8311_53b5#,
      16#983e_5152_ee66_dfab#, 16#a831_c66d_2db4_3210#,
      16#b003_27c8_98fb_213f#, 16#bf59_7fc7_beef_0ee4#,
      16#c6e0_0bf3_3da8_8fc2#, 16#d5a7_9147_930a_a725#,
      16#06ca_6351_e003_826f#, 16#1429_2967_0a0e_6e70#,
      16#27b7_0a85_46d2_2ffc#, 16#2e1b_2138_5c26_c926#,
      16#4d2c_6dfc_5ac4_2aed#, 16#5338_0d13_9d95_b3df#,
      16#650a_7354_8baf_63de#, 16#766a_0abb_3c77_b2a8#,
      16#81c2_c92e_47ed_aee6#, 16#9272_2c85_1482_353b#,
      16#a2bf_e8a1_4cf1_0364#, 16#a81a_664b_bc42_3001#,
      16#c24b_8b70_d0f8_9791#, 16#c76c_51a3_0654_be30#,
      16#d192_e819_d6ef_5218#, 16#d699_0624_5565_a910#,
      16#f40e_3585_5771_202a#, 16#106a_a070_32bb_d1b8#,
      16#19a4_c116_b8d2_d0c8#, 16#1e37_6c08_5141_ab53#,
      16#2748_774c_df8e_eb99#, 16#34b0_bcb5_e19b_48a8#,
      16#391c_0cb3_c5c9_5a63#, 16#4ed8_aa4a_e341_8acb#,
      16#5b9c_ca4f_7763_e373#, 16#682e_6ff3_d6b2_b8a3#,
      16#748f_82ee_5def_b2fc#, 16#78a5_636f_4317_2f60#,
      16#84c8_7814_a1f0_ab72#, 16#8cc7_0208_1a64_39ec#,
      16#90be_fffa_2363_1e28#, 16#a450_6ceb_de82_bde9#,
      16#bef9_a3f7_b2c6_7915#, 16#c671_78f2_e372_532b#,
      16#ca27_3ece_ea26_619c#, 16#d186_b8c7_21c0_c207#,
      16#eada_7dd6_cde0_eb1e#, 16#f57d_4f7f_ee6e_d178#,
      16#06f0_67aa_7217_6fba#, 16#0a63_7dc5_a2c8_98a6#,
      16#113f_9804_bef9_0dae#, 16#1b71_0b35_131c_471b#,
      16#28db_77f5_2304_7d84#, 16#32ca_ab7b_40c7_2493#,
      16#3c9e_be0a_15c9_bebc#, 16#431d_67c4_9c10_0d4c#,
      16#4cc5_d4be_cb3e_42b6#, 16#597f_299c_fc65_7e2a#,
      16#5fcb_6fab_3ad6_faec#, 16#6c44_198c_4a47_5817#);

   procedure Transform (Ctx : in out Context);
   pragma Inline (Transform);

   function Ch (X, Y, Z : Unsigned_64) return Unsigned_64;
   function Maj (X, Y, Z : Unsigned_64) return Unsigned_64;
   function Sigma_0 (X : Unsigned_64) return Unsigned_64;
   function Sigma_1 (X : Unsigned_64) return Unsigned_64;
   function S_0 (X : Unsigned_64) return Unsigned_64;
   function S_1 (X : Unsigned_64) return Unsigned_64;
   pragma Inline (Ch, Maj, Sigma_0, Sigma_1, S_0, S_1);
end SHA2_Generic_64;
