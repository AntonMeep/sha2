with Ada.Streams; use Ada.Streams;

with SHA2_Generic;

package SHA2 is new SHA2_Generic
  (Element       => Stream_Element, Index => Stream_Element_Offset,
   Element_Array => Stream_Element_Array) with
   Pure,
   Preelaborate;
