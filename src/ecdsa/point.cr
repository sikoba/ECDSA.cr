module ECDSA
  class Point
    getter group : Group
    getter x : BigInt
    getter y : BigInt
    getter infinity : Bool

    def initialize(@group : Group, @x : BigInt, @y : BigInt)
      @infinity = false
      raise PointNotInGroup.new("Point (#{x}, #{y}) is not in group #{group}") unless is_in_group?
      @x = @x % @group.p
      @y = @y % @group.p
    end

    def initialize(@group : Group, @infinity : Bool)
      @x = 0.to_big_i
      @y = 0.to_big_i
    end

    def p
      @group.p
    end

    def a
      @group.a
    end

    def b
      @group.b
    end

    def is_in_group? : Bool
      return true if infinity
      (y**2 - x**3 - x*a - b) % p == 0
    end

    def check_group!(other : Point)
      raise PointsGroupMismatch.new if other.group != group
    end

    def ==(other : Point) : Bool
      return false unless group == other.group
      return true if infinity && other.infinity
      return true if x == other.x && y == other.y
      return false
    end

    def +(other : Point ) : Point
      check_group! other

      # cases 1 and 2

      return other if infinity
      return self if other.infinity

      # case 3: identical x coordinates, points distinct or y-ccordinate 0

      if x == other.x && (y + other.y) % p == 0
        return @group.infinity
      end

      # case 4:  different x coordinates
      if x != other.x
        lambda = (y - other.y) * @group.inverse(x - other.x, p) % p
        x_new = (lambda**2 - x - other.x) % p
        y_new = (lambda * (x - x_new) - y) % p
        return Point.new(@group, x_new, y_new)
      end

      # case 5:
      return self.double if self == other

      # we should never get here!
      raise "Point addition failed!"
    end

    def double : Point
      lambda = (3 * x**2 + a) * @group.inverse(2*y, p) % p
      x_new = (lambda**2 - 2*x) % p
      y_new = (lambda*(x - x_new) - y) % p
      return Point.new(@group, x_new, y_new)
    end

    def *(i : Int) : Point
      res = @group.infinity
      v = self

      while i > 0
        res = res + v if i.odd? && !v.is_a?(Nil) && !res.is_a?(Nil)
        v = v.double
        i >>= 1
      end

      return res
    end
  end
end