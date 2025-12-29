/**
 * Test imports one by one to find the issue
 */

console.log('1. Importing uuid...');
import { v4 as uuidv4 } from 'uuid';
console.log('2. UUID imported successfully');

console.log('3. Importing types...');
import { AttackDataset, Attack, FirewallRequest, FirewallResponse, AttackResult } from '../types/core';
console.log('4. Types imported successfully');

console.log('5. Importing FirewallService...');
import { FirewallService } from '../api/firewall';
console.log('6. FirewallService imported successfully');

console.log('7. Importing AttackDatasetManager...');
import { AttackDatasetManager } from '../data/attack-dataset';
console.log('8. AttackDatasetManager imported successfully');

console.log('9. Importing SQLiteDatabase...');
import { SQLiteDatabase } from '../data/database';
console.log('10. SQLiteDatabase imported successfully');

console.log('All imports successful!');

export const testExport = 'working';