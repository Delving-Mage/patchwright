"""Deterministic Maven pom.xml version pinning, both literal and property-ref
forms. This is the Java/Spring dependency-fix path: no LLM, no flakiness."""
from patchwright.remediate import _maven_patch

LITERAL_POM = """<project>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-collections4</artifactId>
      <version>4.0</version>
    </dependency>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>30.0-jre</version>
    </dependency>
  </dependencies>
</project>
"""

PROPERTY_POM = """<project>
  <properties>
    <commons.version>4.0</commons.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-collections4</artifactId>
      <version>${commons.version}</version>
    </dependency>
  </dependencies>
</project>
"""


def test_literal_version_bumped_only_for_target_dep():
    out = _maven_patch(LITERAL_POM, "org.apache.commons:commons-collections4", "4.4")
    assert "<version>4.4</version>" in out
    # the OTHER dependency must be untouched
    assert "<version>30.0-jre</version>" in out
    assert out.count("4.4") == 1


def test_property_reference_bumps_the_property():
    out = _maven_patch(PROPERTY_POM, "org.apache.commons:commons-collections4", "4.4")
    assert "<commons.version>4.4</commons.version>" in out
    # the dependency still references the property (single source of truth)
    assert "${commons.version}" in out


def test_unknown_artifact_returns_none():
    assert _maven_patch(LITERAL_POM, "org.example:does-not-exist", "1.0") is None
