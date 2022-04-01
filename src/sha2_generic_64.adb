pragma Ada_2012;

with Ada.Unchecked_Conversion;
with GNAT.Byte_Swapping;
with System;

package body SHA2_Generic_64 is
   function Initialize return Context is
     ((State => <>, Count => 0, Buffer => (others => <>)));

   procedure Initialize (Ctx : out Context) is
   begin
      Ctx := Initialize;
   end Initialize;

   procedure Update (Ctx : in out Context; Input : String) is
      Buffer : Element_Array (Index (Input'First) .. Index (Input'Last));
      for Buffer'Address use Input'Address;
      pragma Import (Ada, Buffer);
   begin
      Update (Ctx, Buffer);
   end Update;

   procedure Update (Ctx : in out Context; Input : Element_Array) is
      Current : Index := Input'First;
   begin
      while Current <= Input'Last loop
         declare
            Buffer_Index  : constant Index := Ctx.Count rem Block_Length;
            Bytes_To_Copy : constant Index :=
              Index'Min (Input'Length - (Current - Input'First), Block_Length);
         begin
            Ctx.Buffer (Buffer_Index .. Buffer_Index + Bytes_To_Copy - 1) :=
              Input (Current .. Current + Bytes_To_Copy - 1);
            Current   := Current + Bytes_To_Copy;
            Ctx.Count := Ctx.Count + Bytes_To_Copy;

            if Ctx.Buffer'Last < Buffer_Index + Bytes_To_Copy then
               Transform (Ctx);
            end if;
         end;
      end loop;
   end Update;

   function Finalize (Ctx : Context) return Digest is
      Result : Digest;
   begin
      Finalize (Ctx, Result);
      return Result;
   end Finalize;

   procedure Finalize (Ctx : Context; Output : out Digest) is
      use GNAT.Byte_Swapping;
      use System;

      Final_Count : constant Index := Ctx.Count;
      Ctx_Copy    : Context        := Ctx;
   begin
      --  Insert padding
      Update (Ctx_Copy, Element_Array'(0 => 16#80#));

      if Ctx_Copy.Buffer'Last - (Ctx_Copy.Count rem Block_Length) < 16 then
         --  In case not enough space is left in the buffer we fill it up
         Update
           (Ctx_Copy,
            Element_Array'
              (0 ..
                   (Ctx_Copy.Buffer'Last -
                    (Ctx_Copy.Count rem Block_Length)) =>
                 0));
      end if;

      --  Fill rest of the data with zeroes
      Update
        (Ctx_Copy,
         Element_Array'
           (0 ..
                (Ctx_Copy.Buffer'Last - (Ctx_Copy.Count rem Block_Length) -
                 16) =>
              0));

      declare
         --  Shift_Left(X, 3) is equivalent to multiplyng by 8
         Byte_Length_1 : Unsigned_64 :=
           Shift_Right (Unsigned_64 (Final_Count), 61);
         Byte_Length_2 : Unsigned_64 :=
           Shift_Left (Unsigned_64 (Final_Count), 3);

         Byte_Length_1_Buffer : Element_Array (0 .. 7);
         for Byte_Length_1_Buffer'Address use Byte_Length_1'Address;
         pragma Import (Ada, Byte_Length_1_Buffer);

         Byte_Length_2_Buffer : Element_Array (0 .. 7);
         for Byte_Length_2_Buffer'Address use Byte_Length_2'Address;
         pragma Import (Ada, Byte_Length_2_Buffer);
      begin
         if Default_Bit_Order /= High_Order_First then
            Swap8 (Byte_Length_1_Buffer'Address);
            Swap8 (Byte_Length_2_Buffer'Address);
         end if;
         Update (Ctx_Copy, Byte_Length_1_Buffer);
         Update (Ctx_Copy, Byte_Length_2_Buffer);
      end;

      declare
         Buffer  : Element_Array (0 .. 63);
         Current : Index := Buffer'First;
      begin
         for H of Ctx_Copy.State loop
            declare
               Inner_Buffer : Element_Array (0 .. 7);
               for Inner_Buffer'Address use H'Address;
               pragma Import (Ada, Inner_Buffer);
            begin
               if Default_Bit_Order /= High_Order_First then
                  Swap8 (Inner_Buffer'Address);
               end if;
               Buffer (Current + 0 .. Current + 7) := Inner_Buffer;
               Current                             := Current + 8;
               exit when Current >= Digest_Length;
            end;
         end loop;
         Output := Buffer (0 .. Output'Length - 1);
      end;
   end Finalize;

   function Hash (Input : String) return Digest is
      Ctx : Context := Initialize;
   begin
      Update (Ctx, Input);
      return Finalize (Ctx);
   end Hash;

   function Hash (Input : Element_Array) return Digest is
      Ctx : Context := Initialize;
   begin
      Update (Ctx, Input);
      return Finalize (Ctx);
   end Hash;

   procedure Transform (Ctx : in out Context) is
      type Words is array (Natural range <>) of Unsigned_64;

      W : Words (0 .. 79);

      A                        : Unsigned_64 := Ctx.State (0);
      B                        : Unsigned_64 := Ctx.State (1);
      C                        : Unsigned_64 := Ctx.State (2);
      D                        : Unsigned_64 := Ctx.State (3);
      E                        : Unsigned_64 := Ctx.State (4);
      F                        : Unsigned_64 := Ctx.State (5);
      G                        : Unsigned_64 := Ctx.State (6);
      H                        : Unsigned_64 := Ctx.State (7);
      Temporary_1, Temporary_2 : Unsigned_64;
   begin
      declare
         use GNAT.Byte_Swapping;
         use System;

         Buffer_Words : Words (0 .. 15);
         for Buffer_Words'Address use Ctx.Buffer'Address;
         pragma Import (Ada, Buffer_Words);
      begin
         W (0 .. 15) := Buffer_Words;

         if Default_Bit_Order /= High_Order_First then
            --  Take care of endianess
            for I in Buffer_Words'Range loop
               Swap8 (W (I)'Address);
            end loop;
         end if;
      end;

      for I in 16 .. 79 loop
         W (I) := S_1 (W (I - 2)) + W (I - 7) + S_0 (W (I - 15)) + W (I - 16);
      end loop;

      for I in 0 .. 79 loop
         Temporary_1 := H + Sigma_1 (E) + Ch (E, F, G) + K (I) + W (I);
         Temporary_2 := Sigma_0 (A) + Maj (A, B, C);
         H           := G;
         G           := F;
         F           := E;
         E           := D + Temporary_1;
         D           := C;
         C           := B;
         B           := A;
         A           := Temporary_1 + Temporary_2;
      end loop;

      Ctx.State (0) := Ctx.State (0) + A;
      Ctx.State (1) := Ctx.State (1) + B;
      Ctx.State (2) := Ctx.State (2) + C;
      Ctx.State (3) := Ctx.State (3) + D;
      Ctx.State (4) := Ctx.State (4) + E;
      Ctx.State (5) := Ctx.State (5) + F;
      Ctx.State (6) := Ctx.State (6) + G;
      Ctx.State (7) := Ctx.State (7) + H;
   end Transform;

   function Ch (X, Y, Z : Unsigned_64) return Unsigned_64 is
     ((X and Y) xor ((not X) and Z));
   function Maj (X, Y, Z : Unsigned_64) return Unsigned_64 is
     ((X and Y) xor (X and Z) xor (Y and Z));
   function Sigma_0 (X : Unsigned_64) return Unsigned_64 is
     (Rotate_Right (X, 28) xor Rotate_Right (X, 34) xor Rotate_Right (X, 39));
   function Sigma_1 (X : Unsigned_64) return Unsigned_64 is
     (Rotate_Right (X, 14) xor Rotate_Right (X, 18) xor Rotate_Right (X, 41));
   function S_0 (X : Unsigned_64) return Unsigned_64 is
     (Rotate_Right (X, 1) xor Rotate_Right (X, 8) xor Shift_Right (X, 7));
   function S_1 (X : Unsigned_64) return Unsigned_64 is
     (Rotate_Right (X, 19) xor Rotate_Right (X, 61) xor Shift_Right (X, 6));
end SHA2_Generic_64;
