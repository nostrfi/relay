using Nostrfi.Core;

namespace Nostrfi.Relay.Unit.Tests;

public class MultiConcurrentDictionaryTests
{

    private readonly MultiConcurrentDictionary<string, string> _objectUnderTest = new();
    [Fact]
    public void ShouldAddItemToDictionary()
    {
        _objectUnderTest.Add("key", "value");

        _objectUnderTest.ShouldSatisfyAllConditions(
            x => x.Contains("key", "value").Should().BeTrue(),
            x => x.Count.ShouldBe(1)
        );
    }
    
    [Fact]
    public void ShouldAddMultipleValueToSingleKey()
    {
        _objectUnderTest.Add("key", "value1");
        _objectUnderTest.Add("key", "value2");
        _objectUnderTest.Add("key", "value3");

        _objectUnderTest.ShouldSatisfyAllConditions(
            x => x.Contains("key", "value1").Should().BeTrue(),
            x => x.Contains("key", "value2").Should().BeTrue(), 
            x => x.Contains("key", "value3").Should().BeTrue(),
            x => x.Count.ShouldBe(1));
    }
    [Fact]
    public void ShouldAddMultipleItemsToDictionary()
    {
        _objectUnderTest.Add("key1", "value1");
        _objectUnderTest.Add("key2", "value2");
        _objectUnderTest.Add("key3", "value3");

        _objectUnderTest.ShouldSatisfyAllConditions(
            x => x.Contains("key1", "value1").Should().BeTrue(),
            x => x.Contains("key2", "value2").Should().BeTrue(), 
            x => x.Contains("key3", "value3").Should().BeTrue(),
            x => x.Count.ShouldBe(3));
    }
}