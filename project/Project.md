# Final Project 24/25 - Secure Collaborative Document Editor

## Scenario

Your organisation, that is in the market of software security, intends to host a collaborative document editing platform to organize its internal security training tutorials for new members of the organization, and to advertise public tutorials to users of the company's SecDevOps products.
Naturally, the platform itself should be secure to uphold the company's good reputation.
They have assigned to your group, members of the secure software development team of the organisation, the role of designing and implementing a secure solution.


The collaborative document editing platform shall be developed in the form of a modern web application, and support two components:

* **client**: a web page frontend that allows designated company employers to create, manage and configure courses, so that other company employers and/or the general public can consult and navigate its content.
* **server**: a backend with REST endpoints that is called by the client web page. Advanced users may also directly call the REST endpoints.

Quoting a recent document (February 2024, before 👨) issued by the *US White House* on [A Path Toward Secure and
Measurable Software](https://www.whitehouse.gov/wp-content/uploads/2024/02/Final-ONCD-Technical-Report.pdf), _"there are three fundamental dimensions to the risk software poses to the cybersecurity of an organization: the developer process, the software analysis and testing, and the execution environment"_ and _"reframing the discussion on cybersecurity from a reactive to a proactive approach enables a shift in focus from the front-line defenders to the wide range of individuals that have an important part to play in securing the digital ecosystem"_. The focus of our project is precisely to enable a proactive secure software development approach, focusing on the 3 main axes: design, analysis and implementation.

## Requirements

You shall design and build your collaborative document editing platform according to the following general requirements:

- 1. **Interface**:
    * Users shall be able to create, configure, edit and delete documents. A document may consist of multiple sections and paragraphs.
    * Multiple users shall be able to collaboratively edit a document in real-time. Each user will be able to see the changes of others, and document authors will have control over permissions.
    * Documents can be set to public (viewable or editable by anyone).
    * The platform shall be supported by a backend RESTful API reminiscent of, e.g., (a simplification of) the [Google Docs API](https://developers.google.com/docs/api/reference/rest).
- 2. **Authentication**:
    * Non-anonymous users have to authenticate themselves to access the collaborative editing platform. Anonymous users shall only be able to access public content.
    * You may use a minimal authentication method, e.g., password-based.
    * You may secure communications, e.g., enforcing secure HTTPS.
    * You may also consider end-to-end encryption and/or encrypt documents on the server.
    * Note, however, that concrete authentication, communication or encryption methods are **not** a primary focus of this project. In particular, the details of the underlying protocols are not essential for evaluating the security of your proposed solution.
- 3. **Access control**:
    * The system must support some form of *Role-Based Access Control*, such as considering owner, editor and viewer roles. Only users with the owner role should be able to configure document permissions or delete the document.
    * The system shall support granular permissions. Users may restrict access to whole documents or to certain sections or paragraphs of the document. 

You are **not** required to provide more advanced functionality, but if you wish to do so remember to clearly consider and document its security requirements. If you choose to adapt an existing framework, and it is not directly possible to match the outlined requirements, remember to discuss that in your final report.

## Design

Your team shall design the software components needed for the collaborative editing platform, coupled with the security mechanisms to satisfy the requirements outlined above.
You shall seek to adopt a security by design software development methodology, popularly called SecDevOps in the industry. A natural direction is to design a system architecture, specify actors and use/misuse cases, and identify security threats and assumptions before writing a single line of code. A more detailed description of such a general methodology is described in the [NIST Secure Software Development Framework](https://csrc.nist.gov/pubs/sp/800/218/final) and in the [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/).

The security goal of this project is to **protect against external client-side attackers or malicious users**.
You may assume that, aside from vulnerabilities in design or implementation (including third-party dependencies), the server, the client-server communication and the authentication method are trusted.

## Implementation

You shall implement a functional collaborative editing platform that meets the above general requirements and instantiates your proposed secure design.
You can use any technology and programming language for the server/client code that you see fit. 

Beyond familiarity with technology or ease of deployment, your choice shall take into consideration the reliability and the security guarantees offered by each technology. Secure and reliable software procurement is also a job of security developers and teams. 

You are not limited in any way in the existing frameworks that you can use. In fact, you are encouraged to reuse and adapt popular open-source frameworks for your context (to the extent of your interest in exploring other projects). You may also opt to implement a simple prototype *from scratch*. Note that the least source code you develop, and the largest the *trusted* code base you reuse, the more important it is to demonstrate that you understand the configurations of the software components that you reuse, how they fulfil your requirements and which are their security implications. 
As a starting point for exploring existing open-source projects, you may consider the following non-exclusive nor curated list:

* [Etherpad](https://github.com/ether/etherpad-lite)
* [OnlyOffice Document Server](https://github.com/ONLYOFFICE/DocumentServer)
* [Collabora Online](https://github.com/CollaboraOnline/online)
* [CryptPad](https://github.com/xwiki-labs/cryptpad)
* [HedgeDoc](https://github.com/hedgedoc/hedgedoc)
* [MUTE](https://github.com/coast-team/mute)
* [PeerPad](https://github.com/peer-base/peer-pad)

Note that many of these systems are often more concerned with how to reconcile conflicting edits from multiple users at real-time. The way conflicts are prevented or resolved, including versioning, are not a concern for this project.

It is also likely that none of the above will directly meet the requirements above. You may build upon them to include new features involving encryption, access control, authentication, OAuth-based authorization, document sharing, or any other that you find interesting.

## Analysis

You shall also seek to demonstrate that your implementation respects your design and fulfils its security requirements.
You shall describe the security analysis methodology that you have employed to validate your implementation and corroborate the overall security of your system. If you adapt existing frameworks, you are expected to detail the security analysis methodology that they may already have in place and to complement them with additional analyses of your own.

You may check the [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/) for a more detailed description of classical security analyses.
Also, remember the more advanced security analysis tools and/or techniques that we have seen in the practical labs, and explore which can be applied to your context. Your analysis may include, e.g.:

- security guarantees offered by the programming languages;
- adopted secure software design patterns;
- security analysis of dependencies or external libraries;
- adopted mitigations for common vulnerabilities;
- security testing methodologies (manual or automated) that you have put in place;
- source code analysis tools that you have integrated in your development.

## Report

The project report must describe your design, implementation and analysis. The report shall primarily focus on design and analysis decisions, in detriment of implementation details.

Remember that software design, implementation and analysis are not independent phases but are part of a continuous software development process.
Any lessons that you have learned along the way, such as implementation details that have led you to revisit your initial design or design/implementation vulnerabilities that you had not initially predicted, e.g. when designing use and misuse cases, but have found through later analysis, are valuable information to include in the project report.

## Presentation

At the end of the semester, each group will present their assignments during classes. The presentation shall highlight the most relevant security-oriented details of the design/implementation/analysis, as in the written report, and showcase common uses of your service.

## Grading

Each component will have the following percentage in the project's final grade:

| Component              |  %   |
| ---------------------- | ---- |
| Design                 |  25  |
| Implementation         |  25  |
| Analysis               |  30  |
| Presentation & Report  |  20  |
