# Exploding Lips Font Fix

Exploding Lips typically can only be run on a Windows 9x machine as it tries to
access the VGA BIOS character set data.

This fix just adds a new section to the executable with a copy of the character set
and replaces any references to the VGA BIOS with references to the new section.

Exploding Lips can be found here: https://archive.org/details/exploding-lips-full
