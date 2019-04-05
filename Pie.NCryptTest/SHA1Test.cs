using FluentAssertions;
using Pie.NCrypt;
using Xunit;

namespace Pie.NCryptTest
{
    public class SHA1Test
    {
        [Fact]
        public void objects_with_same_content_should_have_the_same_hash_value()
        {
            var object1 = new TestObject
            {
                Field1 = "some value",
                Field2 = 10,
                NestedObject = new NestedObject
                {
                    NestedField1 = 100
                }
            };

            var object2 = new TestObject
            {
                Field1 = "some value",
                Field2 = 10,
                NestedObject = new NestedObject
                {
                    NestedField1 = 100
                }
            };

            var hash1 = new SHA1().HashOf(object1);
            var hash2 = new SHA1().HashOf(object2);

            hash1.Should().Be(hash2);
        }

        [Fact]
        public void objects_with_different_content_should_have_different_hash_values()
        {
            var object1 = new TestObject
            {
                Field1 = "some value",
                Field2 = 10,
                NestedObject = new NestedObject
                {
                    NestedField1 = 100
                }
            };

            var object2 = new TestObject
            {
                Field1 = "some value",
                Field2 = 10,
                NestedObject = new NestedObject
                {
                    NestedField1 = 999  // Different value
                }
            };

            var hash1 = new SHA1().HashOf(object1);
            var hash2 = new SHA1().HashOf(object2);

            hash1.Should().NotBe(hash2);
        }

        [Fact]
        public void should_work_with_anonymous_classes()
        {
            var object1 = new
            {
                Field1 = "some value 1",
                Field2 = "some value 2",
                Field3 = 100
            };

            var object2 = new
            {
                Field1 = "some value 1",
                Field2 = "different value",
                Field3 = 100
            };

            var hash1 = new SHA1().HashOf(object1);
            var hash2 = new SHA1().HashOf(object2);

            hash1.Should().NotBe(hash2);
        }

        [Fact]
        public void objects_with_different_fields_should_have_different_hash_values()
        {
            var object1 = new
            {
                Field1 = "some value 1",
                Field2 = "some value 2",
                Field3 = 100
            };

            var object2 = new
            {
                Field1 = "some value 1",
                Field2 = "some value 2",
                Field3 = 100,
                AdditionalField = "some value"
            };

            var hash1 = new SHA1().HashOf(object1);
            var hash2 = new SHA1().HashOf(object2);

            hash1.Should().NotBe(hash2);
        }

        [Fact]
        public void objects_of_different_classes_but_with_the_same_content_should_have_the_same_hash()
        {
            var object1 = new TestObject
            {
                Field1 = "some value",
                Field2 = 10,
                NestedObject = new NestedObject
                {
                    NestedField1 = 100
                }
            };

            var object2 = new AnotherClassWithSameFields
            {
                Field1 = "some value",
                Field2 = 10,
                NestedObject = new NestedObject
                {
                    NestedField1 = 100
                }
            };

            var hash1 = new SHA1().HashOf(object1);
            var hash2 = new SHA1().HashOf(object2);

            hash1.Should().Be(hash2);
        }

        [Fact]
        public void public_fields_are_included_in_hash_calculation()
        {
            var object1 = new ObjectWithField
            {
                Property = "some value",
                Field = 1
            };
            var object2 = new ObjectWithField
            {
                Property = "some value",
                Field = 2
            };

            var hash1 = new SHA1().HashOf(object1);
            var hash2 = new SHA1().HashOf(object2);

            hash1.Should().NotBe(hash2);
        }
    }

    class NestedObject
    {
        public int NestedField1 { get; set; }
    }

    class TestObject
    {
        public string Field1 { get; set; }
        public int Field2 { get; set; }
        public NestedObject NestedObject { get; set; }
    }

    class AnotherClassWithSameFields
    {
        public string Field1 { get; set; }
        public int Field2 { get; set; }
        public NestedObject NestedObject { get; set; }
    }

    
    public class ObjectWithField
    {
        public int Field;

        public string Property { get; set; }
    }
}