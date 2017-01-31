This folder contains the following


To support identity matching the identity syndicate has an identity information model (IIM)

The IIM is based on the https://schema.org properties and defines what properties can be mapped and the mapping from the participants PN data models to the schema. Every PN Data Model has a mapping between its types and properties and the the IS schema types and properties.

Note that participants PN Data model may define many more types and properties that are passed between parties, the IIM is only about automating and simplifying identity matching between parties.


a. Syndicated Entity

Is a virtual subject that is manufactured from a set of backing PN Data Model subjects that all represent the same subject.
- It has an @id manufactured by the IS, and @type SyndicatedEnity.
- The syndicated entities properties represent one schema from either the IIS or a participants PN Data Model.
- the backing subjects have @ids that represent entities in the real world, and @type and properties from Participants PN Data models.


b. createIIMSEfromPNDataModel - outputs a syndicated entity with a IIM schema from a target IIM schema, and one or more backing subjects and associated PN Data Models.

IN the future can support from more than one

c. CreatePNDataModelSEfromIIMSE - outputs a syndicated entity with an PN data model from a SE with an IIM schema.

d. MergeISIMSE - merges multiple ISIM schema Syndicated Entities into one.

f. createPNDataModelEntityFromSE - creates an actual PN Data Model subject from an SE in that same PN Data Model

Syndicate steps would be
 - find RS PN Data Model
 - create an ISIM schema that is needed by the RS
 - createISIMSEfromPNDataModel - using the desired ISIM schema and backing subjects - output #A
 - use #A and createPNDataModelSEFromISIM to create SE in RS PN Data Model to send to RS
 - RS sends back RS PN data model results to IS

 Query steps would be
 - create ISIMSEFromPNDataModel using the full ISIM schema and passed in query subject and PN data model #1 - output #A
 - If passing to RS to perform query
   - use #A and createPNDataModelSEFromISIMSE to create SE in RS PN data Model to send to RS
   - RS sends back RS PN data model resuts to IS
 - if query index
   - use #A and any necessary mapping
 - With results from > 1 PN Data Model
   - use result and createISIMFromPN data Model to create SE#1 with backing subject PNDM1, SE#2 backing PNDM2, SE#3 backing PNDM3
   - merge SE1, SE2, and SE3 into one SE based in IIS schema - mergeIISIM - note this is used to determine what would like to send.
   - pass merged ISIM into create PNDataModelSEFromISIMSE to create result
