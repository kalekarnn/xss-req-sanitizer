const xssSanitizer = require('./../lib/xss-sanitizer');

//assertion library
const chai = require('chai');
const expect = chai.expect;

// Unit tests
let httpMocks = require('node-mocks-http');
let mockRequest = {};
let mockResponse = {};

// Integration tests
const express = require('express');
const superTest = require('supertest');
const bodyParser = require('body-parser')
const app = express();
let server = {};

describe("XSS Sanitizer Unit Test", () => {

    const nestedBody = {
        nestedPropertyOne: "hello world json"
    };

    beforeEach((done) => {

        mockRequest = httpMocks.createRequest({
            method: 'POST',
            url: '/',
            body: {
                bodyPropertyOne: "<strong>strong hello world</strong><script>alert(/xss/)</script>",
                bodyPropertyTwo: "hello world again",
                bodyPropertyThree: nestedBody,
            },
            query: {
                queryPropertyOne: "<script>10</script>",
                queryPropertyTwo: 20,
                queryPropertyThree: "<h1>xss</h1>",
                queryPropertyFour: [100, 200, 300],
                queryPropertyFive: "<h1>[100, 200, 300]</h1>",
                queryPropertySix: "<tr>20</tr>",
                queryPropertySeven: nestedBody
            },
            params: {
                paramsPropertyOne: "<script>parameter_one</script>",
                paramsPropertyTwo: "parameter_two",
                paramsPropertyThree: "<body>1000</body>",
                paramsPropertyFour: 2000
            }
        });
        mockResponse = httpMocks.createResponse();
        done();
    });

    it("sanitize request body", () => {

        xssSanitizer()(mockRequest, mockResponse, () => {
        });

        expect(mockRequest.body.bodyPropertyOne).to.equal('strong hello world');
        expect(mockRequest.body.bodyPropertyTwo).to.equal('hello world again');
        expect(mockRequest.body.bodyPropertyThree.nestedPropertyOne).to.equal(nestedBody.nestedPropertyOne);
    });

    it("sanitize request query", () => {

        xssSanitizer()(mockRequest, mockResponse, () => {
        });

        expect(mockRequest.query.queryPropertyOne).to.equal('')
        expect(mockRequest.query.queryPropertyTwo).to.equal('20');
        expect(mockRequest.query.queryPropertyThree).to.equal('xss');
        expect(mockRequest.query.queryPropertyFour).to.deep.equal([100, 200, 300]);
        expect(mockRequest.query.queryPropertyFive).to.deep.equal("[100, 200, 300]");
        expect(mockRequest.query.queryPropertySix).to.deep.equal("20");
        expect(mockRequest.query.queryPropertySeven).to.deep.equal(nestedBody);
    });

    it("sanitize request params", () => {

        xssSanitizer()(mockRequest, mockResponse, () => {
        });

        expect(mockRequest.params.paramsPropertyOne).to.equal('')
        expect(mockRequest.params.paramsPropertyTwo).to.equal('parameter_two');
        expect(mockRequest.params.paramsPropertyThree).to.equal('1000');
        expect(mockRequest.params.paramsPropertyFour).to.equal('2000');
    });
});


describe("XSS Sanitizer Integration Test", () => {

    // Setup
    before((done) => {
        app.use(express());
        app.use(bodyParser.json());
        app.use(xssSanitizer());

        app.post('/:paramsPropertyOne/:paramsPropertyTwo', (req, res, next) => {
            res.send({
                sanitizedBody: req.body,
                sanitizedQuery: req.query,
                sanitizedParams: req.params
            });
        });

        app.get('/user', (req, res, next) => {
            res.send({
                sanitizedQuery: req.query,
                sanitizedParams: req.params
            });
        });

        server = app.listen(3000);
        done();
    });

    // Test
    it('should sanitize post request', (done) => {
        superTest(app)
            .post('/10/user?age=<h1>30&userType=admin')
            .send({
                propertyToSanitize: "<script>hello</script>",
                firstName: 'firstname',
                experience: '<body>7<body>'
            })
            .set('Content-Type', 'application/json')
            .set('Accept', 'application/json')
            .expect(200, {
                sanitizedBody: {
                    propertyToSanitize: '',
                    firstName: 'firstname',
                    experience: '7'
                },
                sanitizedQuery: {age: '30', userType: 'admin'},
                sanitizedParams: {paramsPropertyOne: '10', paramsPropertyTwo: 'user'}
            }, done);
    });

    it('should sanitize get request', (done) => {
        superTest(app)
            .get('/user?age=<script>30</script>&userType=admin')
            .set('Accept', 'application/json')
            .expect(200, {
                sanitizedQuery: {age: '', userType: 'admin'},
                sanitizedParams: {}
            }, done);
    });

    after(function () {
        server.close();
    });
});
