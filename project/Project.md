# Final Project - Secure Learning Platform

## Scenario

Your organisation, that is in the market of software security, intends to host a web learning platform to bolster its security training content for members of the organization, and to advertise public tutorials about their SecDevOps products.
Naturally, the platform itself should be secure to uphold the company's good reputation.
They have assigned to your group, members of the secure software development team of the organisation, the role of designing and implementing a secure solution.


The learning platform shall be developed in the form of a modern web application, and support two components:

* **client**: a web page frontend that allows designated company employers to create, manage and configure courses, so that other company employers and/or the general public can consult and navigate its content.
* **server**: a backend with REST endpoints that is called by the client web page. Advanced users may also directly call the REST endpoints.

Quoting a recent document (February 2024) issued by the *US White House* on [A Path Toward Secure and
Measurable Software](https://www.whitehouse.gov/wp-content/uploads/2024/02/Final-ONCD-Technical-Report.pdf), _"there are three fundamental dimensions to the risk software poses to the cybersecurity of an organization: the developer process, the software analysis and testing, and the execution environment"_ and _"reframing the discussion on cybersecurity from a reactive to a proactive approach enables a shift in focus from the front-line defenders to the wide range of individuals that have an important part to play in securing the digital ecosystem"_. The focus of our project is precisely to enable a proactive secure software development approach, focusing on the 3 main axes: design, analysis and implementation.

## Requirements

You shall design and build your learning platform according to the following general requirements:

- 1. **Interface**:
    * It shall be possible to create, configure, edit and delete courses;
    * Each course shall include:
         - A listing of topics;
         - Individually, each topic can be:
             + In a draft state (only visible to the owner) or in a published state;
             + Published topics may be visible to all enrolled users (anyone if public) or to only a select subset of enrolled users;
        - A forum where enrolled users can discuss and ask questions about the topics:
            + Public forums may be configured to allow anonymous/non-authenticated users or enrolled/authenticated users to submit questions;
            + As part of a question, users shall be able to upload images or files.
    * Each student shall have a personal page listing the courses in which he/she is enrolled.
- 2. **Authentication**:
    * Non-anonymous users have to authenticate themselves to access the learning platform;
    * You may use a minimal authentication method, e.g., password-based.
    * You may secure communications, e.g., enforcing secure HTTPS.
    * Note, however, that authentication and secure communication are **not** the primary focus of this project and, in particular, the details of the underlying cryptographic protocols are not essential for evaluating the security of your proposed solution.
- 3. **Access control**:
    * Only users with special administrative powers shall be able to create and delete courses;
    * A course shall have one or more owners who can manage the content and enrolment in the course;
    * Courses can be private (with a list of enrolled students) or public (accessible to anyone);
    * Only enrolled students shall be able to access and post questions on private courses.

You are **not** required to provide more advanced functionality, but if you wish to do so remember to clearly consider and document its security requirements. If you choose to adapt an existing framework, and it is not directly possible to match the outlined requirements, remember to discuss that in your final report.
## Design

Your team shall design the software components needed for the learning platform, coupled with the security mechanisms to satisfy the requirements outlined above.
You shall seek to adopt a security by design software development methodology, popularly called SecDevOps in the industry. A natural direction is to design a system architecture, specify actors and use/misuse cases, and identify security threats and assumptions before writing a single line of code. A more detailed description of such a general methodology is described in the [NIST Secure Software Development Framework](https://csrc.nist.gov/pubs/sp/800/218/final) and in the [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/).

The security goal of this project is to protect against external client-side attackers or malicious users.
You may assume that, aside from vulnerabilities in design or implementation (including third-party dependencies), the server, the client-server communication and the authentication method are trusted.

## Implementation

You shall implement a functional learning platform that meets the above general requirements and instantiates your proposed secure design.
You can use any technology and programming language for the server/client code that you see fit. 

Beyond familiarity with technology or ease of deployment, your choice shall take into consideration the reliability and the security guarantees offered by each technology. Secure and reliable software procurement is also a job of security developers and teams. 

You are not limited in any way in the existing frameworks that you can use. In fact, you are encouraged to reuse and adapt popular open-source LMS frameworks for your context (to the extent of your interest in exploring other projects). You may also opt to implement a simple prototype *from scratch*. Note that the least source code you develop, and the largest the *trusted* code base you reuse, the more important it is to demonstrate that you understand the configurations of the software components that you reuse, how they fulfil your requirements and which are their security implications. 
As a starting point for exploring existing open-source projects, you may consider the following non-exclusive nor curated list:

* [Masteriyo](https://masteriyo.com/)
* [Canvas](https://www.instructure.com/canvas)
* [Moodle](https://moodle.org/)
* [Open edX](https://openedx.org/)
* [Forma LMS](https://www.formalms.org/)
* [Open LMS](https://www.openlms.net/)
* [Odoo](https://www.odoo.com/app/elearning)
* [ATutor](https://atutor.github.io/)

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
