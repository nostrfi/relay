using System.ComponentModel;
using System.Text.Json;
using Nostrfi.Core.Events;

namespace Nostrfi.Relay.Unit.Tests;

public class EventSerializerTests
{
    [Fact]
    [Description("Should serialize the nostr even to the defined class")]
    public void ShouldSerializeNostrEvent()
    {
        // Arrange
        var eventSerializer = new EventSerializer();
     
        // Act
        var serializedEvent = eventSerializer.Deserialize(ValidNostrEvent);

        // Assert
       serializedEvent.ShouldSatisfyAllConditions(
           x => x.ShouldNotBeNull(),
           x => x.Content.ShouldBe("Walled gardens became prisons, and nostr is the first step towards tearing down the prison walls."),
           x => x.Sig.ShouldBe("908a15e46fb4d8675bab026fc230a0e3542bfade63da02d542fb78b2a8513fcd0092619a2c8c1221e581946e0191f2af505dfdf8657a414dbca329186f009262"),
           x => x.Id.ShouldBe("4376c65d2f232afbe9b882a35baa4f6fe8667c4e684749af565f981833ed6a65"),
           x => x.Kind.ShouldBe(1),
           x => x.PubKey.ShouldBe("6e468422dfb74a5738702a8823b9b28168abab8655faacb6853cd0ee15deee93"),
           x => x.CreatedAt.ShouldBe(DateTimeOffset.FromUnixTimeSeconds(1673347337)),
           x => x.Tags.Count.ShouldBe(2)
           );
    }
    
    [Fact]
    [Description("Should throw a JSON Serialization error because the Invalid nostr event has an invalid format ")]
    public void ShouldThrowJsonSerializationExceptionForNotANumber()
    {
        // Arrange
        var eventSerializer = new EventSerializer();
        // Act
        var ex = Assert.Throws<JsonException>(() => eventSerializer.Deserialize(InvalidDateNostEvent));

        // Assert
        ex.Message.ShouldBe("The value supplied is not a number format");
    }
    
    /// <summary>
    /// A sample nostr event 
    /// </summary>
    private static string ValidNostrEvent = """
                                            {
                                                "id": "4376c65d2f232afbe9b882a35baa4f6fe8667c4e684749af565f981833ed6a65",
                                                "pubkey": "6e468422dfb74a5738702a8823b9b28168abab8655faacb6853cd0ee15deee93",
                                                "created_at": 1673347337,
                                                "kind": 1,
                                                "tags": [
                                                    ["e", "3da979448d9ba263864c4d6f14984c423a3838364ec255f03c7904b1ae77f206"],
                                                    ["p", "bf2376e17ba4ec269d10fcc996a4746b451152be9031fa48e74553dde5526bce"]
                                                ],
                                                "content": "Walled gardens became prisons, and nostr is the first step towards tearing down the prison walls.",
                                                "sig": "908a15e46fb4d8675bab026fc230a0e3542bfade63da02d542fb78b2a8513fcd0092619a2c8c1221e581946e0191f2af505dfdf8657a414dbca329186f009262"
                                            }
                                            """;
    
    /// <summary>
    /// Created Date simply transformed to a string instead of being a number
    /// </summary>
    private static string InvalidDateNostEvent  = """
                                                  {
                                                      "id": "4376c65d2f232afbe9b882a35baa4f6fe8667c4e684749af565f981833ed6a65",
                                                      "pubkey": "6e468422dfb74a5738702a8823b9b28168abab8655faacb6853cd0ee15deee93",
                                                      "created_at": "1673347337",
                                                      "kind": 1,
                                                      "tags": [
                                                          ["e", "3da979448d9ba263864c4d6f14984c423a3838364ec255f03c7904b1ae77f206"],
                                                          ["p", "bf2376e17ba4ec269d10fcc996a4746b451152be9031fa48e74553dde5526bce"]
                                                      ],
                                                      "content": "Walled gardens became prisons, and nostr is the first step towards tearing down the prison walls.",
                                                      "sig": "908a15e46fb4d8675bab026fc230a0e3542bfade63da02d542fb78b2a8513fcd0092619a2c8c1221e581946e0191f2af505dfdf8657a414dbca329186f009262"
                                                  }
                                                  """;
}