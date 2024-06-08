package core

// TODO: The plan here is to extract some RPC responses and test the parsing
// against these known drives to ensure long-term compatibility.
// Here are some Discovery Level0 bytes to get started.

// Samsung EVO 860:
// d0raw: [0 0 0 144 0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 16 12 17 0 0 0 0 0 0 0 0 0 0 0 0 2 16 12 31 0 0 0 0 0 0 0 0 0 0 0 0 3 16 28 1 0 0 0 0 0 0 0 0 0 2 0 0 0 0 0 0 0 0 8 0 0 0 0 0 0 0 0 2 2 16 12 0 0 0 9 0 160 0 0 0 0 0 1 2 3 16 16 16 4 0 1 0 0 4 0 9 0 0 0 0 0 0 0]

// Samsung SSD 970 EVO Plus 500GB (NVMe)
// d0raw: [0 0 0 180 0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 16 12 17 0 0 0 0 0 0 0 0 0 0 0 0 2 16 12 9 0 0 0 0 0 0 0 0 0 0 0 0 3 16 28 1 0 0 0 0 0 0 0 0 0 2 0 0 0 0 0 0 0 0 8 0 0 0 0 0 0 0 0 2 2 16 12 0 0 0 9 0 160 0 0 0 0 0 1 2 3 16 16 16 4 0 1 0 0 4 0 9 0 0 0 0 0 0 0 4 2 16 12 0 0 0 0 0 0 0 0 0 0 0 0 4 3 16 16 128 0 0 0 0 0 0 9 0 0 0 8 0 0 0 8]

// Sabrent Rocket 4.0 2TB
// d0raw: [0 0 0 112 0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 16 12 17 0 0 0 0 0 0 0 0 0 0 0 0 2 32 12 65 0 0 0 0 0 0 0 0 0 0 0 3 2 16 16 7 254 0 1 0 0 0 0 0 0 0 0 0 0 0 0 4 2 16 12 0 0 0 0 0 0 0 0]

// SAMSUNG MZ1LB1T9HALS-00007
// d0raw: [0 0 0 180 0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 16 12 17 0 0 0 0 0 0 0 0 0 0 0 0 2 16 12 9 0 0 0 0 0 0 0 0 0 0 0 0 3 16 28 1 0 0 0 0 0 0 0 0 0 2 0 0 0 0 0 0 0 0 8 0 0 0 0 0 0 0 0 2 2 16 12 0 0 0 9 0 160 0 0 0 0 0 1 2 3 16 16 16 4 0 1 0 0 4 0 9 0 0 0 0 0 0 0 4 2 16 12 2 1 0 0 0 0 0 0 0 0 0 0 4 3 16 16 128 0 0 0 0 0 0 9 0 0 0 8]
