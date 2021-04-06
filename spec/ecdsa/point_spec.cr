require "./../spec_helper"

describe ECDSA::Point do
  simple_group = ECDSA::Group.new(
    name: :custom,
    p: 59.to_big_i,
    a: 17.to_big_i,
    b: 5.to_big_i,
    gx: 4.to_big_i,
    gy: 14.to_big_i,
    n: 37.to_big_i
  )

  describe "#initialize" do
    it "does not allow points not in group" do
      # (y**2 - x**3 - x*a - b) % p != 0
      y = 1.to_big_i
      x = 2.to_big_i
      group = ECDSA::Group.new(
        name: :custom,
        p: 11.to_big_i,
        a: 1.to_big_i,
        b: 6.to_big_i,
        gx: 2.to_big_i,
        gy: 7.to_big_i,
        n: 13.to_big_i
      )

      expect_raises(ECDSA::PointNotInGroup) do
        point = ECDSA::Point.new(
          group: group,
          x: x,
          y: y
        )
      end
    end

    it "assigns @x and @y mod @group.p" do
      group = ECDSA::Group.new(
        name: :custom,
        p: 11.to_big_i,
        a: 1.to_big_i,
        b: 6.to_big_i,
        gx: 2.to_big_i,
        gy: 7.to_big_i,
        n: 13.to_big_i
      )

      point = ECDSA::Point.new(
          group: group,
          x: 13.to_big_i,
          y: 15.to_big_i
      )

      # 10 % 3
      point.x.should eq 2
      # 24 % 3
      point.y.should eq 4
    end
  end

  describe "==" do
    it "false when different group" do
      group1 = ECDSA.get_group(:secp256k1)
      group2 = ECDSA.get_group(:secp256r1)

      point1 = ECDSA::Point.new(
        group1,
        BigInt.new("c3da9c0e67011b7b72172259e5184719f6ac1c01e7649fd6a898afb001a95a18", base: 16),
        BigInt.new("54bdbfebb31b270f816ddba928cc7c4bde69555738861ca9512d3a9ce1fa1db6", base: 16)
      )
      point2 = ECDSA::Point.new(
        group2,
        BigInt.new("38782195218204771874797181360279529530259336100522971835928508134553605578239"),
        BigInt.new("97996409821752143758621047960435857171910161741100894466537116983997853367842")
      )

      (point1 == point2).should eq false
    end

    it "Inf == Inf" do
      group = ECDSA.get_group(:secp256k1)
      inf1 = ECDSA::Point.new(group, true)
      inf2 = ECDSA::Point.new(group, true)

      (inf1 == inf2).should eq true
    end

    it "true by position" do
      group = ECDSA.get_group(:secp256k1)
      point1 = ECDSA::Point.new(
        group,
        BigInt.new("c3da9c0e67011b7b72172259e5184719f6ac1c01e7649fd6a898afb001a95a18", base: 16),
        BigInt.new("54bdbfebb31b270f816ddba928cc7c4bde69555738861ca9512d3a9ce1fa1db6", base: 16)
      )
      point2 = ECDSA::Point.new(
        group,
        BigInt.new("c3da9c0e67011b7b72172259e5184719f6ac1c01e7649fd6a898afb001a95a18", base: 16),
        BigInt.new("54bdbfebb31b270f816ddba928cc7c4bde69555738861ca9512d3a9ce1fa1db6", base: 16)
      )

      (point1 == point2).should eq true
    end

    it "false by position" do
      group = ECDSA.get_group(:secp256k1)
      point1 = ECDSA::Point.new(
        group,
        BigInt.new("85750571623004729612724195992546455699737722186140433904856360140942337282226"),
        BigInt.new("67986584995344148237593928014284887806013188798536248847920281527612827590628")
      )
      point2 = ECDSA::Point.new(
        group,
        BigInt.new("79574032687728714890896466032897815583335374670217033676698438552684612551747"),
        BigInt.new("26886140704816001178787988088519797139959960851138892645352858294238056557784")
      )

      (point1 == point2).should eq false
    end
  end

  describe "+" do
    it "Inf + P = P" do
      group = ECDSA.get_group(:secp256k1)
      inf = ECDSA::Point.new(group, true)
      point = ECDSA::Point.new(
        group,
        BigInt.new("85750571623004729612724195992546455699737722186140433904856360140942337282226"),
        BigInt.new("67986584995344148237593928014284887806013188798536248847920281527612827590628")
      )

      (inf + point).should eq point
      (point + inf).should eq point
    end

    it "any + any = any" do
      p = ECDSA::Point.new(
        simple_group,
        4.to_big_i,
        14.to_big_i
      )
      q = ECDSA::Point.new(
        simple_group,
        8.to_big_i,
        2.to_big_i
      )
      pq = ECDSA::Point.new(
        simple_group,
        56.to_big_i,
        24.to_big_i
      )

      (p + q).should eq pq
    end

    it "P + P = 2P" do
      p = ECDSA::Point.new(
        simple_group,
        4.to_big_i,
        14.to_big_i
      )
      double_p = ECDSA::Point.new(
        simple_group,
        8.to_big_i,
        2.to_big_i
      )

      (p + p).should eq double_p
    end
  end

  describe "#double" do
    it do
      p = ECDSA::Point.new(
        simple_group,
        4.to_big_i,
        14.to_big_i
      )
      double_p = ECDSA::Point.new(
        simple_group,
        8.to_big_i,
        2.to_big_i
      )

      (p.double).should eq double_p
    end

    it do
      q = ECDSA::Point.new(
        simple_group,
        56.to_big_i,
        24.to_big_i
      )
      double_q = ECDSA::Point.new(
        simple_group,
        22.to_big_i,
        17.to_big_i
      )

      (q.double).should eq double_q
    end
  end

  describe "*" do
    it do
      p = ECDSA::Point.new(
        simple_group,
        4.to_big_i,
        14.to_big_i
      )
      triple_p = ECDSA::Point.new(
        simple_group,
        56.to_big_i,
        24.to_big_i
      )

      (p * 3).should eq triple_p
    end

    it do
      q = ECDSA::Point.new(
        simple_group,
        56.to_big_i,
        24.to_big_i
      )
      penta_q = ECDSA::Point.new(
        simple_group,
        20.to_big_i,
        12.to_big_i
      )

      (q * 5).should eq penta_q
    end
  end
end