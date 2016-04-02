PROVIDE_HIDDEN (mutable_data_begin = ADDR(.got.plt));
PROVIDE_HIDDEN (mutable_data_end = mutable_data_begin + SIZEOF(.got.plt) + SIZEOF(.data));
SECTIONS {} INSERT BEFORE .text;
