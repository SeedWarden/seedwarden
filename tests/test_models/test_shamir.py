from random import randint

from seedwarden.models.shamir import Interpolator, Polynomial, Scalar, Share


def test_success():
    poly = Polynomial(3)
    qrs = [poly.get_share(Scalar(x + 1)).serialize_qr() for x in range(6)]

    def get_share() -> Share:
        return Share.deserialize_qr(qrs[randint(0, len(qrs) - 1)])

    ip = Interpolator(get_share())
    while ip.num_shares < ip.threshold:
        ip.add_share(get_share())

    assert poly.secret == ip.secret
