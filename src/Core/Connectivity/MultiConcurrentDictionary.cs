using System.Collections;
using System.Collections.Concurrent;
using System.Diagnostics;

namespace Nostrfi.Core;

public class MultiConcurrentDictionary<TKey, TValue> : IEnumerable<KeyValuePair<TKey, TValue[]>>
{
    private class Bag : HashSet<TValue>
    {
        public bool IsDiscarded { get; set; }
    }

    private readonly ConcurrentDictionary<TKey, Bag> _dictionary = new();
    public int Count => _dictionary.Count;

    public bool Add(TKey key, TValue value)
    {
        var spinWait = new SpinWait();
        while (true)
        {
            var bag = _dictionary.GetOrAdd(key, _ => []);
            lock (bag)
            {
                if (!bag.IsDiscarded) return bag.Add(value);
            }

            spinWait.SpinOnce();
        }
    }

    public bool AddOrReplace(TKey key, TValue value)
    {
        Remove(key, value);
        return Add(key, value);
    }

    public bool Remove(TKey key, out TValue[] items)
    {
        if (_dictionary.TryRemove(key, out var x))
        {
            items = x.ToArray();
            return true;
        }

        items = null;
        return false;
    }

    public bool TryGetValues(TKey key, out TValue[] values)
    {
        if (!TryGetNameFromBag(key, out var bag))
        {
            values = null;
            return false;
        }

        var isDiscarded = CheckDiscardStatusAndFetchValues(bag, out values);
        if (!isDiscarded) return true;
        values = null;
        return false;
    }

    private bool TryGetNameFromBag(TKey key, out Bag bag)
    {
        return _dictionary.TryGetValue(key, out bag);
    }

    private static bool CheckDiscardStatusAndFetchValues(Bag bag, out TValue[] values)
    {
        lock (bag)
        {
            values = bag.ToArray();
            return bag.IsDiscarded;
        }
    }

    private bool Remove(TKey key, TValue value)
    {
        SpinWait spinWait = new();
        while (true)
        {
            if (!_dictionary.TryGetValue(key, out var bag)) return false;

            bool shouldSpinAndRetry;
            lock (bag)
            {
                shouldSpinAndRetry = RemoveValueFromBag(bag, value);
            }

            if (!shouldSpinAndRetry) return TryRemoveBagFromDictionary(key, bag);
            spinWait.SpinOnce();
        }
    }

    private static bool RemoveValueFromBag(Bag bag, TValue value)
    {
        if (bag.IsDiscarded) return true;
        if (!bag.Remove(value)) return false;

        if (bag.Count == 0)
        {
            bag.IsDiscarded = true;
        }

        return false;

    }

    private bool TryRemoveBagFromDictionary(TKey key, Bag bag)
    {
        var keyRemoved = _dictionary.TryRemove(key, out var currentBag);
        Debug.Assert(keyRemoved, $"Key {key} was not removed");
        Debug.Assert(bag == currentBag, $"Removed wrong bag");
        return true;
    }

    public bool Contains(TKey key, TValue value)
    {
        if (!_dictionary.TryGetValue(key, out var bag)) return false;
        lock (bag) return !bag.IsDiscarded && bag.Contains(value);
    }

    public bool Contains(TKey key, IEnumerable<TValue> values)
    {
        if (!_dictionary.TryGetValue(key, out var bag)) return false;
        lock (bag) return !bag.IsDiscarded && values.Any(bag.Contains);
    }
    public bool ContainsKey(TKey key) => _dictionary.ContainsKey(key);

    public ICollection<TKey> Keys => _dictionary.Keys;

    public IEnumerator<KeyValuePair<TKey, TValue[]>> GetEnumerator()
    {
        foreach (var key in _dictionary.Keys)
        {
            if (TryGetValues(key, out var values))
            {
                yield return new KeyValuePair<TKey, TValue[]>(key, values);
            }
        }
    }

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();


    public bool Remove(string key)
    {
        var genericKey = (TKey) Convert.ChangeType(key, typeof(TKey));
        return _dictionary.TryRemove(genericKey, out _);
    }
}