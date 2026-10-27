"""
=====================================================================
 dsa.py  -  BACKEND: all Data Structures & Algorithms (no web code here)
=====================================================================
  1. Linked list      : StudentLinkedList  (master in-memory storage)
  2. Hash map         : HashMap            (roll lookup, marks groups)
  3. Sorting          : merge_sort, quick_sort
  4. Searching        : linear_search, binary_search
  5. Arrays / vectors : Python lists are used wherever arrays are needed
  BONUS               : run_benchmark (linear vs binary search)
=====================================================================
"""

import random
import time


# =====================================================================
#  DSA 1 : LINKED LIST (master storage)
# =====================================================================
class Node:
    __slots__ = ("data", "next")

    def __init__(self, data):
        self.data = data
        self.next = None


class StudentLinkedList:
    """Singly linked list with head and tail pointers (O(1) append)."""

    def __init__(self):
        self.head = self.tail = None
        self.size = 0

    def append(self, student):
        node = Node(student)
        if self.head is None:
            self.head = self.tail = node
        else:
            self.tail.next = node
            self.tail = node
        self.size += 1

    def remove(self, roll):
        prev, cur = None, self.head
        while cur:
            if cur.data.roll == roll:
                if prev is None:
                    self.head = cur.next
                else:
                    prev.next = cur.next
                if cur is self.tail:
                    self.tail = prev
                self.size -= 1
                return True
            prev, cur = cur, cur.next
        return False

    def to_array(self):
        arr, cur = [], self.head
        while cur:
            arr.append(cur.data)
            cur = cur.next
        return arr


# =====================================================================
#  DSA 2 : HASH MAP (separate chaining, auto-resize)
# =====================================================================
class HashMap:
    def __init__(self, capacity=16):
        self.capacity = capacity
        self.buckets = [[] for _ in range(capacity)]
        self.count = 0

    @staticmethod
    def _hash(key):                                  # djb2 string hash
        h = 5381
        for ch in str(key):
            h = ((h << 5) + h + ord(ch)) & 0xFFFFFFFF
        return h

    def _bucket(self, key):
        return self.buckets[self._hash(key) % self.capacity]

    def put(self, key, value):
        bucket = self._bucket(key)
        for pair in bucket:
            if pair[0] == key:
                pair[1] = value
                return
        bucket.append([key, value])
        self.count += 1
        if self.count / self.capacity > 0.75:
            self._resize()

    def get(self, key, default=None):
        for k, v in self._bucket(key):
            if k == key:
                return v
        return default

    def contains(self, key):
        return any(k == key for k, _ in self._bucket(key))

    def items(self):
        for bucket in self.buckets:
            for k, v in bucket:
                yield k, v

    def _resize(self):
        old = list(self.items())
        self.capacity *= 2
        self.buckets = [[] for _ in range(self.capacity)]
        self.count = 0
        for k, v in old:
            self.put(k, v)


# =====================================================================
#  DSA 3 : SORTING
# =====================================================================
def merge_sort(arr, key, descending=False):
    """Stable merge sort, O(n log n). Returns a NEW sorted list."""
    if len(arr) <= 1:
        return list(arr)
    mid = len(arr) // 2
    left = merge_sort(arr[:mid], key, descending)
    right = merge_sort(arr[mid:], key, descending)
    merged, i, j = [], 0, 0
    while i < len(left) and j < len(right):
        a, b = key(left[i]), key(right[j])
        if (a >= b) if descending else (a <= b):
            merged.append(left[i]); i += 1
        else:
            merged.append(right[j]); j += 1
    merged.extend(left[i:])
    merged.extend(right[j:])
    return merged


def quick_sort(arr, key, lo=0, hi=None):
    """In-place quick sort with random pivot."""
    if hi is None:
        hi = len(arr) - 1
    while lo < hi:
        p = random.randint(lo, hi)
        arr[p], arr[hi] = arr[hi], arr[p]
        pivot, i = key(arr[hi]), lo
        for j in range(lo, hi):
            if key(arr[j]) < pivot:
                arr[i], arr[j] = arr[j], arr[i]
                i += 1
        arr[i], arr[hi] = arr[hi], arr[i]
        if i - lo < hi - i:
            quick_sort(arr, key, lo, i - 1)
            lo = i + 1
        else:
            quick_sort(arr, key, i + 1, hi)
            hi = i - 1


# =====================================================================
#  DSA 4 : SEARCHING
# =====================================================================
def linear_search(arr, target, key=lambda x: x):
    """O(n): look at every element."""
    for i, item in enumerate(arr):
        if key(item) == target:
            return i
    return -1


def binary_search(arr, target, key=lambda x: x):
    """O(log n): array MUST be sorted."""
    lo, hi = 0, len(arr) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        k = key(arr[mid])
        if k == target:
            return mid
        if k < target:
            lo = mid + 1
        else:
            hi = mid - 1
    return -1


def run_benchmark(sizes=(1_000, 10_000, 100_000, 200_000), queries=100):
    """Returns rows: (n, linear_ms, binary_ms, speedup)."""
    rows = []
    for n in sizes:
        data = [f"R{i:07d}" for i in range(n)]            # sorted by construction
        targets = [random.choice(data) for _ in range(queries)]
        t0 = time.perf_counter()
        for t in targets:
            linear_search(data, t)
        lin = (time.perf_counter() - t0) * 1000
        t0 = time.perf_counter()
        for t in targets:
            binary_search(data, t)
        binr = (time.perf_counter() - t0) * 1000
        rows.append((n, lin, binr, lin / binr if binr else 0))
    return rows
