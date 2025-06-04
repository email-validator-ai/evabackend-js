#!/usr/bin/env node

/**
 * Test script for the distributed SMTP EVA system
 * Tests communication between AWS EC2 and dedicated SMTP server
 */

const axios = require('axios');
const colors = require('colors');

// Configuration
const config = {
  awsEc2Url: process.env.AWS_EC2_URL || 'http://localhost:3000',
  smtpServerUrl: process.env.SMTP_SERVER_URL || 'http://localhost:3001',
  smtpApiKey: process.env.SMTP_API_KEY || 'your-api-key-here',
  testEmails: [
    'test@gmail.com',
    'valid@outlook.com',
    'invalid@nonexistentdomain123456.com',
    'disposable@10minutemail.com'
  ]
};

class DistributedSystemTest {
  constructor() {
    this.results = {
      awsEc2Health: false,
      smtpServerHealth: false,
      smtpServerAuth: false,
      endToEndVerification: false,
      batchVerification: false,
      errors: []
    };
  }

  async runAllTests() {
    console.log('🚀 Starting distributed SMTP EVA system tests...\n'.blue.bold);

    try {
      await this.testAwsEc2Health();
      await this.testSmtpServerHealth();
      await this.testSmtpServerAuth();
      await this.testEndToEndVerification();
      await this.testBatchVerification();

      this.printResults();

    } catch (error) {
      console.error('❌ Test suite failed:'.red.bold, error.message);
      process.exit(1);
    }
  }

  async testAwsEc2Health() {
    console.log('1️⃣  Testing AWS EC2 instance health...'.yellow);

    try {
      const response = await axios.get(`${config.awsEc2Url}/api/health`, {
        timeout: 10000
      });

      if (response.status === 200 && response.data.status === 'healthy') {
        console.log('   ✅ AWS EC2 instance is healthy'.green);
        this.results.awsEc2Health = true;
      } else {
        throw new Error(`Unexpected response: ${response.status}`);
      }
    } catch (error) {
      console.log('   ❌ AWS EC2 health check failed:'.red, error.message);
      this.results.errors.push(`AWS EC2 Health: ${error.message}`);
    }
    console.log('');
  }

  async testSmtpServerHealth() {
    console.log('2️⃣  Testing SMTP server health...'.yellow);

    try {
      const response = await axios.get(`${config.smtpServerUrl}/api/health`, {
        timeout: 10000
      });

      if (response.status === 200 && response.data.status === 'healthy') {
        console.log('   ✅ SMTP server is healthy'.green);
        this.results.smtpServerHealth = true;
      } else {
        throw new Error(`Unexpected response: ${response.status}`);
      }
    } catch (error) {
      console.log('   ❌ SMTP server health check failed:'.red, error.message);
      this.results.errors.push(`SMTP Server Health: ${error.message}`);
    }
    console.log('');
  }

  async testSmtpServerAuth() {
    console.log('3️⃣  Testing SMTP server authentication...'.yellow);

    try {
      // Test without API key (should fail)
      try {
        await axios.get(`${config.smtpServerUrl}/api/smtp/status`, {
          timeout: 5000
        });
        throw new Error('Authentication should have failed without API key');
      } catch (error) {
        if (error.response && error.response.status === 401) {
          console.log('   ✅ Authentication properly rejects requests without API key'.green);
        } else {
          throw error;
        }
      }

      // Test with API key (should succeed)
      const response = await axios.get(`${config.smtpServerUrl}/api/smtp/status`, {
        headers: {
          'X-API-Key': config.smtpApiKey
        },
        timeout: 10000
      });

      if (response.status === 200 && response.data.success) {
        console.log('   ✅ Authentication works with valid API key'.green);
        this.results.smtpServerAuth = true;
      } else {
        throw new Error(`Unexpected authenticated response: ${response.status}`);
      }

    } catch (error) {
      console.log('   ❌ SMTP server authentication test failed:'.red, error.message);
      this.results.errors.push(`SMTP Server Auth: ${error.message}`);
    }
    console.log('');
  }

  async testEndToEndVerification() {
    console.log('4️⃣  Testing end-to-end email verification...'.yellow);

    try {
      const testEmail = config.testEmails[0]; // Use gmail.com for reliable test
      console.log(`   Testing with: ${testEmail}`.cyan);

      const response = await axios.post(`${config.awsEc2Url}/api/email/verify`, {
        email: testEmail,
        checkDNS: true,
        checkMX: true,
        checkSMTP: true,
        checkCatchAll: false // Skip for faster testing
      }, {
        headers: {
          'Content-Type': 'application/json'
        },
        timeout: 60000 // Longer timeout for SMTP verification
      });

      if (response.status === 200 && response.data.success) {
        const result = response.data.data;
        console.log(`   ✅ Email verification completed in ${result.processingTime}ms`.green);
        
        // Check if all levels were processed
        if (result.checks.syntax) console.log('      - Level 1 (Syntax): ✅'.gray);
        if (result.checks.dns) console.log('      - Level 3 (DNS): ✅'.gray);
        if (result.checks.mx) console.log('      - Level 4 (MX): ✅'.gray);
        if (result.checks.smtp) {
          console.log('      - Level 5 (SMTP): ✅'.gray);
          console.log(`        Response: ${result.checks.smtp.smtpResponse}`.gray);
        }

        this.results.endToEndVerification = true;
      } else {
        throw new Error(`Unexpected verification response: ${response.status}`);
      }

    } catch (error) {
      console.log('   ❌ End-to-end verification failed:'.red, error.message);
      this.results.errors.push(`End-to-End Verification: ${error.message}`);
    }
    console.log('');
  }

  async testBatchVerification() {
    console.log('5️⃣  Testing batch verification...'.yellow);

    try {
      const testEmails = config.testEmails.slice(0, 2); // Test with 2 emails
      console.log(`   Testing batch with: ${testEmails.join(', ')}`.cyan);

      const response = await axios.post(`${config.awsEc2Url}/api/email/verify/batch`, {
        emails: testEmails,
        checkDNS: true,
        checkMX: true,
        checkSMTP: true,
        checkCatchAll: false,
        maxConcurrent: 2
      }, {
        headers: {
          'Content-Type': 'application/json'
        },
        timeout: 120000 // Even longer timeout for batch
      });

      if (response.status === 200 && response.data.success) {
        const results = response.data.data;
        console.log(`   ✅ Batch verification completed for ${results.length} emails`.green);
        
        results.forEach((result, index) => {
          const status = result.isValid ? '✅' : '❌';
          console.log(`      ${index + 1}. ${result.email}: ${status}`.gray);
        });

        this.results.batchVerification = true;
      } else {
        throw new Error(`Unexpected batch response: ${response.status}`);
      }

    } catch (error) {
      console.log('   ❌ Batch verification failed:'.red, error.message);
      this.results.errors.push(`Batch Verification: ${error.message}`);
    }
    console.log('');
  }

  printResults() {
    console.log('📊 Test Results Summary'.blue.bold);
    console.log('='.repeat(50).blue);

    const tests = [
      { name: 'AWS EC2 Health', result: this.results.awsEc2Health },
      { name: 'SMTP Server Health', result: this.results.smtpServerHealth },
      { name: 'SMTP Server Auth', result: this.results.smtpServerAuth },
      { name: 'End-to-End Verification', result: this.results.endToEndVerification },
      { name: 'Batch Verification', result: this.results.batchVerification }
    ];

    let passedTests = 0;
    tests.forEach(test => {
      const status = test.result ? '✅ PASS'.green : '❌ FAIL'.red;
      console.log(`${test.name.padEnd(25)} ${status}`);
      if (test.result) passedTests++;
    });

    console.log('='.repeat(50).blue);
    console.log(`Total: ${passedTests}/${tests.length} tests passed`.bold);

    if (this.results.errors.length > 0) {
      console.log('\n🚨 Errors encountered:'.red.bold);
      this.results.errors.forEach((error, index) => {
        console.log(`${index + 1}. ${error}`.red);
      });
    }

    if (passedTests === tests.length) {
      console.log('\n🎉 All tests passed! Your distributed system is working correctly.'.green.bold);
      process.exit(0);
    } else {
      console.log('\n⚠️  Some tests failed. Please check the configuration and try again.'.yellow.bold);
      process.exit(1);
    }
  }
}

// Main execution
if (require.main === module) {
  // Check if colors module is available
  try {
    require('colors');
  } catch (error) {
    console.log('Installing colors module for better output...');
    require('child_process').execSync('npm install colors', { stdio: 'inherit' });
    console.log('Colors module installed. Please run the test again.');
    process.exit(0);
  }

  const tester = new DistributedSystemTest();
  tester.runAllTests().catch(error => {
    console.error('Test execution failed:', error);
    process.exit(1);
  });
}

module.exports = DistributedSystemTest; 