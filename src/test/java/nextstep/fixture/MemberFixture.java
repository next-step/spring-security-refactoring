package nextstep.fixture;

import nextstep.app.domain.Member;

import java.util.Set;

public class MemberFixture {
    public static final Member TEST_ADMIN_MEMBER = new Member("a@a.com", "password", "a", "", Set.of("ADMIN"));
    public static final Member TEST_USER_MEMBER = new Member("b@b.com", "password", "b", "", Set.of());

}
