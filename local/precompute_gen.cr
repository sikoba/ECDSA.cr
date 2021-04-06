require "../src/ecdsa.cr"

module EcdsaPrecompute

  s  = "module ECDSA\n"
  s += "\n"
  s += "  PRECOMPUTED = {\n"
  s += "\n"

  # ECDSA::CURVES.keys.each do |curve|
  [:secp256k1].each do |curve|

    group = ECDSA.get_group(curve, false)
    g = group.g
    d = group.d

    s += "    :#{curve} => [\n"

    a = Array(ECDSA::Point).new
    p = g
    (0..d-1).each do |i|
      a << p
      s += "        [BigInt.new(\"#{a[i].x}\", base: 10),\n"
      s += "         BigInt.new(\"#{a[i].y}\", base: 10)],\n"
      p = p.slow_mul(2)
    end
    s += "    ],\n\n"

  end
    # end of file

  s += "  }\n\n"
  s += "end\n"

  # write

  File.write("./local/precomputed.cr", s)

end